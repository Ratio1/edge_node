from extensions.serving.mixins_llm.llm_utils import LlmCT


class LlmTokenizerMixin(object):
  def __init__(self, *args, **kwargs):
    super(LlmTokenizerMixin, self).__init__(*args, **kwargs)
    return

  def add_context_to_request(self, request, context: list):
    """
    Adds context to the request.

    Parameters
    ----------
    request : str
        the request
    context : list
        the context

    Returns
    -------
    str
        the request with context
    """
    formatted_context = "\n\n".join(
      f"## Context {i + 1}:\n{segment.strip()}"
      for i, segment in enumerate(context)
      if isinstance(segment, str)
    )
    return  (
        f"{request.strip()}\n\n"
        f"---\n"
        f"# Context data:\n\n"
        f"{formatted_context}\n"
        # f"Feel free to use or ignore the context as you see fit.\n" # use only when using reasoning model
        f"---"
    )

  def _get_prompt_from_template(self, messages, context=None):
    """
    Uses Jinja template to generate a prompt.

    Parameters
    ----------
    messages : list[dict]
        List of dictionaries, where each dictionary represents a message in the conversation.
        Each dictionary should have the keys 'role' and 'content'.
        The 'role' key should be one of 'user', 'assistant', or 'system'.
    context : list or str, optional
        the context for the prompt - CURRENTLY DISABLED

    Returns
    -------
    str
        full prompt

    Raises
    ------
    ValueError
        _description_
    """
    if not isinstance(messages, list):
      msg = f"`messages` must be a list of dicts. Received {type(messages)}"
      self.maybe_exception(msg)
    # endif type check

    chat = []
    system_info = None
    request = None
    for message in messages:
      role = message.get(LlmCT.ROLE_KEY, None)
      content = message.get(LlmCT.DATA_KEY, None)
      if role is None or content is None:
        msg = f"Each message in `messages` must have a `role` and `content`. Invalid message:\n{message}"
        self.maybe_exception(msg)

      if not isinstance(content, str):
        msg = f"The `content` of each message must be a string. Invalid message:\n{message}"
        self.maybe_exception(msg)

      # endif role/content check
      if role == LlmCT.SYSTEM_ROLE:
        system_info = {LlmCT.ROLE_KEY: LlmCT.SYSTEM_ROLE, LlmCT.DATA_KEY: content}
      elif role in [LlmCT.REQUEST_ROLE, LlmCT.REPLY_ROLE]:
        chat.append({LlmCT.ROLE_KEY: role, LlmCT.DATA_KEY: content})
      # endif role check
    # endfor messages

    if self.cfg_history_limit is not None:
      limit = max(int(self.cfg_history_limit), 0)
      chat = chat[-limit:]
    # endif history limit

    if system_info is not None:
      chat = [system_info] + chat
    # endif create system info

    if True:
      if context is not None and isinstance(context, (list, str)) and len(context) > 0:
        if isinstance(context, str):
          context = [context]
        # endif context is str
        context = [c for c in context if isinstance(c, str) and len(c) > 0]
        if len(context) > 0 and len(chat) > 0 and chat[-1][LlmCT.ROLE_KEY] != LlmCT.SYSTEM_ROLE:
          chat[-1][LlmCT.DATA_KEY] = self.add_context_to_request(chat[-1][LlmCT.DATA_KEY], context)
        # endif non-empty chat
      # endif context provided
    # The context feature is disabled until further improvements are made.

    self.P(f"Processing chat:\n{chat}")

    from_template = self.tokenizer.apply_chat_template(
      chat, tokenize=False,
      add_generation_prompt=self.cfg_add_generation_prompt # TODO: check if False is ok and when is not
    )
    return from_template
