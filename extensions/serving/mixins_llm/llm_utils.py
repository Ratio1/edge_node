from transformers import LogitsProcessor
from typing import Sequence
import torch as th
# LLM constants

B_INST, E_INST = "[INST]", "[/INST]"
B_SYS, E_SYS = "<<SYS>>\n", "\n<</SYS>>\n\n"


class LlmCT:
  P_USER_START = B_INST
  P_USER_END = E_INST
  P_ROUND_START = '<s>'
  P_ROUND_END = '</s>'
  P_SYS_START = B_SYS
  P_SYS_END = E_SYS

  HIST = 'history'
  REQ = 'request'
  RES = 'response'
  SYS = 'system_info'
  CTX = 'context'

  PRED = 'prediction'
  TEXT = 'text'
  TKNS = 'tokens'
  PRMP = 'prompt'
  TPS  = 'tps'

  ADDITIONAL = 'ADDITIONAL'
  MESSAGES = 'MESSAGES'
  TEMPERATURE = 'TEMPERATURE'
  TOP_P = 'TOP_P'
  MAX_TOKENS = 'MAX_TOKENS'
  CONTEXT = 'CONTEXT'
  VALID_CONDITION = 'VALID_CONDITION'
  PROCESS_METHOD = 'PROCESS_METHOD'
  REQUEST_ID = 'REQUEST_ID'
  REQUEST_TYPE = 'REQUEST_TYPE'
  VALID_MASK = 'VALID_MASK'

  # Constants for encoding a prompt using chat templates
  REQUEST_ROLE = 'user'
  REPLY_ROLE = 'assistant'
  SYSTEM_ROLE = 'system'
  ROLE_KEY = 'role'
  DATA_KEY = 'content'

  EE_HF_TOKEN = 'EE_HF_TOKEN'

  LLAMA3_CHAT_TEMPLATE = """{{ bos_token }}
{% if messages[0]['role'] == 'system' %}
    {% set loop_messages = messages[1:] %}
    {% set system_message = '<|start_header_id|>' + 'system' + '<|end_header_id|>\n\n' + messages[0]['content'].strip() + '<|eot_id|>' %}
{% else %}
    {% set loop_messages = messages %}
    {% set system_message = '' %}
{% endif %}

{% for message in loop_messages %}
    {% if (message['role'] == 'user') != (loop.index0 % 2 == 0) %}
        {{ raise_exception('Conversation roles must alternate user/assistant/user/assistant/...') }}
    {% endif %}

    {% if loop.index0 == 0 %}
        {{ system_message }}
    {% endif %}

    {{ '<|start_header_id|>' + message['role'] + '<|end_header_id|>\n\n' + message['content'].strip() + '<|eot_id|>' }}

    {% if loop.last and message['role'] == 'user' and add_generation_prompt %}
        {{ '<|start_header_id|>' + 'assistant' + '<|end_header_id|>\n\n' }}
    {% endif %}
{% endfor %}
"""

  MISTRAL_CHAT_TEMPLATE = """{% if messages[0]['role'] == 'system' %}
    {% set loop_messages = messages[1:] %}
    {% set system_message = messages[0]['content'].strip() + '\n\n' %}
{% else %}
    {% set loop_messages = messages %}
    {% set system_message = '' %}
{% endif %}

{{ bos_token }}
{% for message in loop_messages %}
    {% if (message['role'] == 'user') != (loop.index0 % 2 == 0) %}
        {{ raise_exception('Conversation roles must alternate user/assistant/user/assistant/...') }}
    {% endif %}

    {% if loop.index0 == 0 %}
        {% set content = system_message + message['content'] %}
    {% else %}
        {% set content = message['content'] %}
    {% endif %}

    {% if message['role'] == 'user' %}
        {{ '[INST] ' + content.strip() + ' [/INST]' }}
    {% elif message['role'] == 'assistant' %}
        {{ ' ' + content.strip() + eos_token }}
    {% endif %}
{% endfor %}
"""

# END LLM constants


"""LOGITS PROCESSOR SECTION"""
if True:
  # 1. Per-row Temperature with greedy fallback
  class PerSampleTemperature(LogitsProcessor):
    """
    Vectorised temperature scaling that *also* supports T == 0 -> greedy.
    - temps : list / 1-D tensor with length == batch_size.

    Efficiency notes
    ----------------
    1.   We pre-compute 1/temperature so the forward pass uses a fast
         in-place multiply instead of a divide.  CUDA division is 2–4×
         slower than multiplication on most architectures.
    2.   Greedy rows (T==0) are handled in *one* scatter op, not a loop,
         following PyTorch best-practice for gather/scatter workloads.
    3.   All tensor work stays on device; no `.item()` syncs.
    """

    def __init__(self, temps: Sequence[float]):
      t = th.as_tensor(temps, dtype=th.float32)

      if (t < 0).any():
        raise ValueError("Temperature must be non-negative (T >= 0).")  # mirror HF contract

      self.greedy_mask = (t == 0)  # True -> row wants greedy
      safe_t = t.clone()
      safe_t[self.greedy_mask] = 1.0  # avoid divide-by-zero
      self.inv_t = 1.0 / safe_t  # store reciprocal for faster mul
      self.has_greedy = self.greedy_mask.any()

    def __call__(self, input_ids: th.Tensor, scores: th.Tensor) -> th.Tensor:
      # --- 1  Scale logits (scores *= 1/T)  ---------------------------
      scores.mul_(self.inv_t.to(scores.device).unsqueeze(-1))

      # --- 2  Force arg-max for rows with T == 0  ---------------------
      if self.has_greedy:  # host flag -> no GPU sync cost
        gmask = self.greedy_mask.to(scores.device)  # (B,)
        row_idx = th.nonzero(gmask, as_tuple=True)[0]  # rows that are greedy
        col_idx = scores[gmask].argmax(dim=-1)  # winning token per row

        # ❶ Set full row to −inf in bulk, ❷ restore the winner to 0
        scores[gmask] = -float("inf")  # boolean-mask assignment is fused.
        scores[row_idx, col_idx] = 0.0

      return scores

    def __repr__(self):
      return f"{self.__class__.__name__}(temps={self.inv_t.tolist()})"

  # 2. Per-row Top-p (nucleus) sampling
  class PerSampleTopP(LogitsProcessor):
    """
    Vectorised nucleus-filtering with a *different* p for every row.
    For each sequence we keep the smallest set of tokens whose cum-prob >= p,
    then zero-out the rest by setting their logit to −inf.
    """

    def __init__(self, top_ps: Sequence[float], min_tokens_to_keep: int = 1):
      ps = th.as_tensor(top_ps, dtype=th.float32)
      if ((ps <= 0) | (ps > 1)).any():
        raise ValueError("top_p must be in (0, 1].")
      self.ps = ps
      self.min_keep = min_tokens_to_keep

    def __call__(self, input_ids: th.Tensor, logits: th.Tensor) -> th.Tensor:
      # 1  Convert logits->probs; sort descending to get cumsum easily
      probs, idx = logits.softmax(dim=-1).sort(dim=-1, descending=True)
      cumprobs = probs.cumsum(dim=-1)

      # 2  For each row, mask tokens once cum prob exceeds its own p
      cut_mask = cumprobs > self.ps.to(logits.device).unsqueeze(-1)
      cut_mask[..., : self.min_keep] = False  # guarantee >=min_keep tokens

      # 3  Translate mask back to original vocab order in-place
      logits_sorted = logits.gather(1, idx)  # same shape as probs
      logits_sorted[cut_mask] = -float("inf")  # drop overflow tokens
      logits.scatter_(1, idx, logits_sorted)  # write back

      return logits

    def __repr__(self):
      return f"{self.__class__.__name__}(top_ps={self.ps.tolist()}, min_tokens_to_keep={self.min_keep})"

  # 3. Per-row Repetition Penalty
  class PerSampleRepetitionPenalty(LogitsProcessor):
    """
    Implements the algorithm from HF's RepetitionPenaltyLogitsProcessor
    but with a vector of penalties, one per sequence, and **no Python loop**.

    Idea
    ----
    • Build a boolean mask `seen_tok` of shape (B, V) marking which tokens
      already appeared in the prefix.  This is a sparse-to-dense scatter but
      stays cheap for typical batch sizes (V≈50 k, B<32).
    • Apply `torch.where` to modify only those logits.
    """

    def __init__(self, penalties: Sequence[float]):
      p = th.as_tensor(penalties, dtype=th.float32)
      if (p <= 0).any():
        raise ValueError("repetition_penalty must be > 0.")
      self.pen = p

    def __call__(self, input_ids: th.Tensor, logits: th.Tensor) -> th.Tensor:
      B, V = logits.shape
      device = logits.device

      # 1  Build (B,V) mask of tokens present in each prefix
      seen_tok = th.zeros((B, V), dtype=th.bool, device=device)
      seen_tok.scatter_(1, input_ids, True)  # O(B·seq_len) write

      # 2  Broadcast row-wise penalty factors
      pen = self.pen.to(device).unsqueeze(-1)  # (B,1) -> (B,V) via broadcast

      # 3  Apply formula in one fused where
      #     > if l > 0: l = l / p
      #     > else:     l = l * p
      pos_mask = logits > 0
      logits_penalised = th.where(pos_mask, logits / pen, logits * pen)

      # 4  Merge: only change logits that belong to seen tokens
      logits.copy_(th.where(seen_tok, logits_penalised, logits))

      return logits

    def __repr__(self):
      return f"{self.__class__.__name__}(penalties={self.pen.tolist()})"

  # 4. Per-row Max-new-tokens gate
  class PerSampleMaxLength(LogitsProcessor):
    """
    Soft EOS gate used instead of the global `max_new_tokens` arg.
    As soon as *any* row reaches its personal length budget, we force
    its logits to predict EOS and let the rest of the batch continue.

    This is the technique recommended by HF maintainers for per-row
    stopping without re-batching.
    """

    def __init__(
            self,
            prompt_lens: Sequence[int],
            max_new_tokens: Sequence[int],
            eos_token_id: int,
    ):
      self.target_len = (th.as_tensor(prompt_lens) +
                         th.as_tensor(max_new_tokens))
      self.eos_id = eos_token_id

    def __call__(self, input_ids: th.Tensor, logits: th.Tensor) -> th.Tensor:
      cur_len = input_ids.size(1)
      done_mask = cur_len >= self.target_len.to(input_ids.device)  # (B,)

      # Bulk-mask done rows; boolean index is cheap/no-op when all-False.
      logits[done_mask] = -float("inf")
      logits[done_mask, self.eos_id] = 0.0
      return logits

    def __repr__(self):
      return f"{self.__class__.__name__}(target_len={self.target_len.tolist()}, eos_id={self.eos_id})"
"""END LOGITS PROCESSOR SECTION"""


