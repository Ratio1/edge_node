from ratio1.ipfs import R1FSEngine

from extensions.serving.base.base_llm_serving import BaseLlmServing as BaseServingProcess
from transformers import AutoTokenizer, AutoModel
import re
import pickle
from pypdf import PdfReader
from docx import Document

from docarray import BaseDoc, DocList
from docarray.typing import NdArray
from vectordb import HNSWVectorDB


"""
  TODO:
  - try https://huggingface.co/jinaai/jina-clip-v2
  - integrate vectordb library
  - add segmentation of the context
  - support multiple sets of context(maybe a dictionary of format {key: list[doc1, doc2, ...]})
  - add context to a single set
  - change context for a single set
  - reset all sets of context
  
"""


__VER__ = '0.1.0.0'
MAX_SEGMENT_SIZE = 1000
MAX_SEGMENT_OVERLAP = 50
WORD_FIND_REGEX = r'\b(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[a-zA-Z]+(?:\'[a-z]+)?|[0-9]+(?:\.[0-9]+)?|[^\s\w])\b'
DEFAULT_NUMBER_OF_RESULTS = 10
DOC_EMBEDDING_SIZE = 1024
DEBUG_DOC_EMB = True


class DocEmbCt:
  REQUEST_TYPE = 'REQUEST_TYPE'
  REQUEST_ID = 'REQUEST_ID'
  REQUEST_PARAMS = 'REQUEST_PARAMS'

  CONTEXT_ID = 'CONTEXT_ID'
  DOCUMENTS_CID = 'DOCUMENTS_CID'
  DOCUMENTS = 'DOCUMENTS'

  QUERY = 'QUERY'
  ADD_DOC = 'ADD_DOC'
  LIST_CONTEXT = 'LIST_CONTEXT'
  K = 'K'

  BAD_REQUEST = 'BAD_REQUEST'
  ERROR_MESSAGE = 'ERROR_MESSAGE'
  DEFAULT_REQUEST_TYPE = QUERY
  REQUEST_TYPES = [QUERY, ADD_DOC, LIST_CONTEXT]

  DOC_KEY = 'doc'
  DOCS_KEY = 'docs'
  URL_KEY = 'url'
  AVAILABLE_DOCS = ['doc', 'docs']
# endclass


_CONFIG = {
  **BaseServingProcess.CONFIG,

  'MAX_BATCH_SIZE': 32,

  "SUPPORTED_REQUEST_TYPES": DocEmbCt.REQUEST_TYPES,
  # TODO: activate this after fixing r1fs init in base_serving_process
  #  (fix log parameter name)
  "R1FS_ENABLED": False,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class NaeuralDoc(BaseDoc):
  # TODO: find how the size of this can be configurable in case of different model.
  #  this should be done at initialization time only in order to avoid vectordb issues.
  # TODO: encrypt the text for db and decrypt it when needed.
  text: str = ''
  embedding: NdArray[DOC_EMBEDDING_SIZE]
  idx: int = -1
# endclass


class DocSplitter:
  """
  Class for splitting one document or a list of documents into segments.
  """
  def __init__(
      self, max_segment_size: int = MAX_SEGMENT_SIZE,
      max_segment_overlap: int = MAX_SEGMENT_OVERLAP,
  ):
    """
    Constructor for the DocSplitter class.

    Parameters
    ----------
    max_segment_size : int - the maximum size of a segment in words
    max_segment_overlap : int - the maximum overlap between segments in words
    """
    self.__max_segment_size = max_segment_size
    self.__max_segment_overlap = max_segment_overlap
    return

  def document_atomizing(self, document: str):
    """
    Atomize a document into words.

    Parameters
    ----------
    document : str - the document to be atomized

    Returns
    -------
    list[str] - the list of words
    """
    return re.findall(WORD_FIND_REGEX, document)

  def compute_best_overlap(self, text_size: int):
    """
    Compute the best overlap for the segments, while considering the text size and the maximum segment size.

    Parameters
    ----------
    text_size : int - the size of the text

    Returns
    -------
    int - the best overlap for the segments
    """
    # In case the text size is smaller than the maximum segment size, we do not need any overlap.
    if text_size <= self.__max_segment_size:
      return 0
    # We want the last segment to be as long as possible.
    best_overlap, best_last_segment_length = 0, 0
    # We cannot have an overlap larger than the maximum segment overlap.
    max_overlap = min(self.__max_segment_overlap, self.__max_segment_size - 1)
    min_overlap = int(max_overlap // 2)
    # The overlap between the segments helps us keep as much information as possible.
    # Thus, we start from half of the maximum overlap and go up to the maximum overlap.
    for overlap in range(min_overlap, max_overlap + 1):
      last_segment_length = (text_size - self.__max_segment_size) % (self.__max_segment_size - overlap)
      if last_segment_length > best_last_segment_length:
        best_overlap, best_last_segment_length = overlap, last_segment_length
      # endif last segment length is better
    # endfor each overlap
    return best_overlap

  def split_document(self, document: str):
    """
    Split a document into segments.

    Parameters
    ----------
    document : str - the document to be split

    Returns
    -------
    list[str] - the list of segments
    """
    # Break the document in words.
    words = self.document_atomizing(document)
    # Compute the best overlap for the segments.
    overlap = self.compute_best_overlap(text_size=len(words))
    increment_step = max(1, self.__max_segment_size - overlap)
    # Split the document into segments.
    segments = [
      ' '.join(words[i:i + self.__max_segment_size])
      for i in range(0, max(1, len(words) - overlap), increment_step)
    ]
    return segments

  def split_documents(self, documents: list[str]):
    """
    Split a list of documents into segments.
    Each document will be split into segments on its own, but the segmentations will be concatenated.

    Parameters
    ----------
    documents : list[str] - the list of documents to be split

    Returns
    -------
    list[str] - the list of segments
    """
    segmentations = [self.split_document(doc) for doc in documents]
    return sum(segmentations, [])
# endclass DocSplitter


class BaseDocEmbServing(BaseServingProcess):
  CONFIG = _CONFIG
  def __init__(self, **kwargs):
    super(BaseDocEmbServing, self).__init__(**kwargs)
    self.__dbs = {}
    self.__doc_splitter = DocSplitter()
    return

  def D(self, msg, **kwargs):
    if DEBUG_DOC_EMB:
      self.P(msg, **kwargs)
    return

  def context_identifier_to_name(self, context):
    return None if context == 'default' else context.removeprefix('context_') if isinstance(context, str) else context

  def __context_identifier(self, context):
    return 'default' if context is None else f'context_{context}'

  def __db_cache_workspace(self, context):
    return self.os_path.join(self.get_models_folder(), 'vectordb', self.cfg_model_name, context)

  def get_embedding_size(self):
    return DOC_EMBEDDING_SIZE

  def __backup_contexts(self):
    """
    Backup the contexts to ensure their persistence.
    """
    self.P(f"Backing up contexts: {list(self.__dbs.keys())}")
    self.persistence_serialization_save(
      obj={
        'contexts': list(self.__dbs.keys()),
        'embedding_size': self.get_embedding_size()
      }
    )
    return

  def __maybe_load_backup(self):
    """
    In case of persisted contexts, load them.
    """
    saved_data = self.persistence_serialization_load()
    if saved_data is not None:
      contexts = saved_data.get('contexts', [])
      embedding_size = saved_data.get('embedding_size', None)
      for context in contexts:
        if context not in self.__dbs:
          self.__dbs[context] = HNSWVectorDB[NaeuralDoc](workspace=self.__db_cache_workspace(context))
        # endif sanity check in case of db already loaded
      # endfor each context
    # endif saved data available
    return

  def on_init(self):
    super(BaseDocEmbServing, self).on_init()
    self.__maybe_load_backup()
    self.r1fs = R1FSEngine(
      logger=self.log
    )
    return

  def _setup_llm(self):
    # just override this method as the base class has a virtual method that raises an exception
    return

  def _get_device_map(self):
    return self.device

  def load_tokenizer(self, model_id, cache_dir, token):
    self.tokenizer = AutoTokenizer.from_pretrained(
      model_id,
      cache_dir=self.cache_dir,
      use_auth_token=self.hf_token
    )
    return

  def load_pretrained_model(self, model_id, **kwargs):
    return AutoModel.from_pretrained(model_id, **kwargs)

  def _warmup(self):
    warmup_context = [
      "The Tesla Cybertruck is a battery electric pickup truck built by Tesla, Inc. since 2023.[6] Introduced as a "
      "concept vehicle in November 2019, it has a body design reminiscent of low-polygon modelling, consisting of flat "
      "stainless steel sheet panels.\nTesla initially planned to produce the vehicle in 2021, but it entered "
      "production in 2023 and was first delivered to customers in November. Three models are offered: a tri-motor "
      "all-wheel drive (AWD) \"Cyberbeast\", a dual-motor AWD model, and a rear-wheel drive (RWD) model, with EPA "
      "range estimates of 250–340 miles (400–550 km), varying by model.\nAs of December 2023, the Cybertruck is "
      "available only in North America.",

      "Am facut acest chec pufos cu cacao de atata ori si pentru atat de multe ocazii, incat cred ca-l pot face cu "
      "ochii inchisi. Checul este unul din deserturile clasice romanesti. Il faceau bunicile noastre, mamele noastre "
      "si acum este randul nostru sa ducem reteta mai departe. Este atat de iubit si de popular incat tuturor le "
      "place. Mama este una dintre marile iubitoarele acestui chec, la fel ca mine, de altfel. Alaturi de reteta de "
      "cozonac, checul este desertul pe care il facea cel mai des. Ni l-a facut toata copilaria si imi amintesc cu "
      "drag si nostalgie de feliile groase de chec presarate din abundenta cu zahar pudra. Era minunat pentru micul "
      "dejun, dar si ca gustare, alaturi de un pahar cu lapte sau de o cafea. Il manacam imediat si rar ne mai ramanea "
      "si a doua zi.\nReteta aceasta de chec pufos cu cacao este putin diferita de cea pe care o facea mama. Am "
      "modificat-o in asa fel incat sa fie usor de facut si sa reduc la minim riscul de a da gres. Cel mai important "
      "lucru atunci cand faceti aceasta reteta este sa bateti cat mai bine albusurile. Trebuie sa incorporati cat mai "
      "mult aer in ele. Pentru asta puteti folosi un stand-mixer sau pur si simplu un mixer manual. Puteti incerca si "
      "cu un tel, insa va dura considerabil mai mult timp. Aveti grija cand separati albusurile! Nicio picatura de "
      "galbenus nu trebuie sa ajunga in ele. La fel, nicio picatura de grasime, altfel nu se vor bate cum trebuie. Si "
      "bolul trebuie sa fie bine spalat si degresat cu putina zeama de lamaie sau otet.Evitati sa folositi boluri din "
      "plastic pentru ca nu se vor curata la fel de bine."
    ]
    warmup1 = warmup_context[:1]
    warmup2 = warmup_context
    warmup4 = warmup_context + warmup_context
    self.P(f'Model warming up with {len(warmup1)} texts')
    self.embed_texts(warmup_context[:1])
    self.P(f'Model warming up with {len(warmup2)} texts')
    self.embed_texts(warmup2)
    self.P(f'Model warmup done')

    return

  """PREPROCESS OF REQUESTS"""
  if True:
    def processed_bad_request(self, msg, request_id=None, predict_kwargs=None):
      return {
        DocEmbCt.REQUEST_ID: request_id,
        DocEmbCt.REQUEST_TYPE: DocEmbCt.BAD_REQUEST,
        DocEmbCt.REQUEST_PARAMS: {},
        DocEmbCt.ERROR_MESSAGE: msg,
        'PREDICT_KWARGS': predict_kwargs or {},
      }

    """FILE EXTRACTION"""
    if True:
      def extract_from_txt(self, file_path: str):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
          result = f.readlines()
        # endwith open
        return result

      def extract_from_pdf(self, file_path: str):
        warnings = []
        reader = PdfReader(file_path)
        if getattr(reader, "is_encrypted", False):
          # Best-effort: attempt empty password; otherwise fail with a useful warning.
          try:
            reader.decrypt("")
          except Exception as e:
            warnings.append("PDF is encrypted and could not be decrypted.")
            return ([], warnings)
        # endif encrypted

        text_chunks = []
        for page in reader.pages:
          try:
            t = page.extract_text() or ""
            if t is not None and len(t.strip()) > 0:
              text_chunks.append(t)
          except Exception as e:
            # Continue best-effort if one page fails
            warnings.append(f"Failed to extract text from a PDF page due to: {e}")
            continue
        # endfor each page

        total_texts_len = sum(len(t.strip()) if isinstance(t, str) else 0 for t in text_chunks)
        if total_texts_len == 0:
          warnings.append("No selectable text found in PDF (it may be scanned images).")
        return text_chunks, warnings

      def extract_from_docx(self, file_path: str):
        doc = Document(file_path)
        # Join paragraph text; tables/runs could be added if you need richer extraction
        return [
          p.text
          for p in doc.paragraphs if p.text is not None and len(p.text.strip()) > 0
        ]
    """END FILE EXTRACTION"""

    def maybe_merge_lines(
        self,
        documents: list[str],
        document_max_length: int = MAX_SEGMENT_SIZE,
    ):
      """
      Merge lines that are too short into a single line.
      Parameters
      ----------
      documents : list[str] - the list of documents

      Returns
      -------

      """
      if not isinstance(documents, list) or len(documents) == 0:
        return documents
      # endif documents is not a list or is empty
      merged_documents = []
      current_doc = ""
      for doc in documents:
        if not isinstance(doc, str):
          continue
        # endif doc is not a string
        doc = doc.strip()
        if len(doc) == 0:
          continue
        # endif doc is empty
        if (len(current_doc) + len(doc) + 1) <= document_max_length:
          if len(current_doc) > 0:
            current_doc += "\n" + doc
          else:
            current_doc = doc
          # endif current_doc is not empty
        else:
          if len(current_doc) > 0:
            merged_documents.append(current_doc)
            current_doc = ""
          # endif current_doc is not empty
          merged_documents.append(doc)
        # endif doc is short or long
      # endfor each document
      if len(current_doc) > 0:
        merged_documents.append(current_doc)
      # endif current_doc is not empty after the loop
      return merged_documents

    def retrieve_documents_from_path(self, documents_path: str):
      path_ext = self.os_path.splitext(documents_path)[1].lower()
      documents = None
      try:
        if path_ext == '.pkl':
          with open(documents_path, 'rb') as f:
            documents_data = pickle.load(f)
            documents = documents_data.get(DocEmbCt.DOCUMENTS, [])
          # endwith open documents_path
        elif path_ext == '.txt':
          documents = self.extract_from_txt(documents_path)
        elif path_ext == '.pdf':
          documents, warnings = self.extract_from_pdf(documents_path)
        elif path_ext in ['.docx', '.docs']:
          documents = self.extract_from_docx(documents_path)
        # endif supported extension
        documents = self.maybe_merge_lines(documents)
        documents_str = "\n".join(documents)[:100]
        self.P(f"Extracted {len(documents)} documents from {documents_path}. Sample:\n{documents_str}", color='g')
      except Exception as e:
        self.P(f"Error reading documents from {documents_path}: {e}", color='r')
      return documents

    """VALIDATION OF REQUESTS"""
    if True:
      def doc_embedding_valid_docs(self, documents: list[str]):
        is_bad_request, processed_request_params, err_msg = False, {}, ""
        if not isinstance(documents, list) or not all([isinstance(x, str) for x in documents]):
          additional = ""
          if isinstance(documents, list):
            non_str_types = [type(x) for x in documents if not isinstance(x, str)]
            non_str_types = list(set(non_str_types))
            additional = f" containing non string types: {non_str_types}"
          # endif list, but not all strings
          err_msg = (f"Error! For ADD_DOC request `{DocEmbCt.REQUEST_PARAMS}` documents must be a list of strings."
                     f"Received {type(documents)}{additional}.")
          is_bad_request = True
        else:
          processed_request_params = {'docs': documents}
        # endif valid docs_value
        return is_bad_request, processed_request_params, err_msg

      def doc_embedding_valid_doc(self, doc_value):
        is_bad_request, processed_request_params, err_msg = False, {}, ""
        if not isinstance(doc_value, str):
          err_msg = (f"Error! For ADD_DOC request `{DocEmbCt.REQUEST_PARAMS}` the `doc` key must be a string."
                     f"Received {type(doc_value)}.")
          is_bad_request = True
        else:
          processed_request_params = {'docs': [doc_value]}
        # endif valid doc_value
        return is_bad_request, processed_request_params, err_msg

      def doc_embedding_valid_url(self, url_value):
        is_bad_request, processed_request_params, err_msg = False, {}, ""
        err_msg = "Error! The `url` key is not available for the moment."
        is_bad_request = True
        return is_bad_request, processed_request_params, err_msg

      def doc_embedding_validate_request_params(self, request_type, request_params):
        """
        Method for validating the request parameters.

        Parameters
        ----------
        request_type : str - the request type
        request_params : dict - the request parameters

        Returns
        -------

        is_bad_request : bool - whether the request is bad
        processed_request_params : dict - the processed request parameters
        err_msg : str - the error message if any
        """
        is_bad_request, processed_request_params, err_msg = False, {}, ""
        # Normalize the keys to uppercase.
        uppercase_params = {k.upper(): v for k, v in request_params.items()}

        if request_type == DocEmbCt.LIST_CONTEXT:
          # No additional parameters are needed
          pass
        elif request_type == DocEmbCt.QUERY:
          query_value = uppercase_params.get(DocEmbCt.QUERY, None)
          if query_value is None or not isinstance(query_value, str):
            err_msg = (f"Error! `{DocEmbCt.REQUEST_PARAMS}` must contain a '{DocEmbCt.QUERY}' key with a string value. "
                       f"Received {type(query_value)}.")
            is_bad_request = True
          else:
            processed_request_params = {
              DocEmbCt.QUERY: query_value,
              DocEmbCt.K: uppercase_params.get(DocEmbCt.K, 10)
            }
          # endif query not in request params
        elif request_type == DocEmbCt.ADD_DOC:
          documents_cid = uppercase_params.get(DocEmbCt.DOCUMENTS_CID, None)
          context_id = uppercase_params.get(DocEmbCt.CONTEXT_ID, None)
          if documents_cid is None:
            err_msg = (f"Error! `{DocEmbCt.REQUEST_PARAMS}` must contain a '{DocEmbCt.DOCUMENTS_CID}' key. "
                       f"Received {documents_cid}.")
            is_bad_request = True
          else:
            documents_path = self.r1fs.get_file(cid=documents_cid, secret=context_id)
            if documents_path is None:
              err_msg = (f"Error! `{DocEmbCt.REQUEST_PARAMS}` must contain a '{DocEmbCt.DOCUMENTS_CID}' key with a valid cid. "
                         f"Received {documents_cid}.")
              is_bad_request = True
            else:
              documents = self.retrieve_documents_from_path(documents_path)
              is_bad_request, processed_request_params, err_msg = self.doc_embedding_valid_docs(
                documents=documents,
              )
            # endif documents_path is None
          # endif documents_cid is not None
        else:
          # This should not happen. We already checked the request type and this is only a sanity check.
          err_msg = f"Error! `{DocEmbCt.REQUEST_TYPE}` value must be one of {DocEmbCt.REQUEST_TYPES}. Received {request_type}."
          is_bad_request = True
        # endif request_params checks
        if not is_bad_request:
          processed_request_params[DocEmbCt.CONTEXT_ID] = uppercase_params.get(DocEmbCt.CONTEXT_ID, None)
        # endif not bad request
        return is_bad_request, processed_request_params, err_msg
    """END VALIDATION OF REQUESTS"""

    def get_additional_metadata(self):
      return {
        'MODEL_NAME': self.cfg_model_name,
        'EMBEDDING_SIZE': self.get_embedding_size(),
        'MAX_SEGMENT_SIZE': MAX_SEGMENT_SIZE,
        'CONTEXTS': [
          self.context_identifier_to_name(context) for context in
          list(self.__dbs.keys())
        ]
      }

    def _pre_process(self, inputs):
      """
      Pre-process the inputs for the model.
      The expected input is a dictionary with the key 'DATA' containing a list of dictionaries.
      Each dictionary represents a message received from the network.
      Each valid dictionary must contain the `JEEVES_CONTENT` key with the content of the request in the following
      format:
      # 1. Will add doc to the default context
      {
        'REQUEST_ID': 'request_id_1',
        'REQUEST_TYPE': 'ADD_DOC',
        'REQUEST_PARAMS': {
          'doc': 'text1',
        }
      }
      # 2. Will add docs to the default context
      {
        'REQUEST_ID': 'request_id_2',
        'REQUEST_TYPE': 'ADD_DOC',
        'REQUEST_PARAMS': {
          'docs': ['text2', 'text3'],
        }
      }
      # 3. Will add content from https://www.example.com to `context1`.
      #   This is unavailable for the moment.
      {
        'REQUEST_ID': 'request_id_3',
        'REQUEST_TYPE': 'ADD_DOC',
        'REQUEST_PARAMS': {
          'url': 'https://www.example.com',
          'context': 'context1',
        }
      }
      # 4. Will compute the closest 10 documents to 'query1' in the default context
      {
        'REQUEST_ID': 'request_id_4',
        'REQUEST_TYPE': 'QUERY',
        'REQUEST_PARAMS': {
          'query': 'query1',
          'k': 10,
        }
      }
      `REQUEST_TYPE` can be one of the following:
      - ADD_DOC:
        The request params must contain either a 'doc' or a 'docs' key.
        The 'doc' key must have a string value representing the document to be added to the specified context.
        The 'docs' key must have a list of strings representing the documents to be added to the specified context.
        The 'url' key is unavailable for the moment.
        If both keys are present, the 'docs' key will be used.
        If no context is specified through the 'context' key in the "REQUEST_PARAMS" dict,
        the default context will be used.

      - QUERY:
        The request params must contain a 'query' key with a string value representing the query to be solved.
        The 'k' key is optional and must have an integer value representing the number of closest documents to be returned.
        If the 'k' key is not present, the default value of 10 will be used.
        Same as the 'ADD_DOC' request, the 'context' key is used to specify the context to be used.

      - LIST_CONTEXT:
        No additional parameters are needed.
        This request will return the list of available contexts.

      Parameters
      ----------
      inputs : dict - the inputs for the prediction

      Returns
      -------

      processed_requests : list[dict] - the processed requests

      """
      lst_inputs = inputs.get('DATA', [])
      self.P(f"Pre-processing {len(lst_inputs)} requests.")
      relevant_input_ids = []
      cnt_total_inputs = len(inputs)

      processed_requests = []
      for i, inp in enumerate(lst_inputs):
        if self.check_relevant_input(inp):
          relevant_input_ids.append(i)
        else:
          continue
        is_bad_request = False
        msg = ""
        jeeves_content = inp.get('JEEVES_CONTENT')

        # Will be included in the jeeves_content
        predict_kwargs = {}
        normalized_input = {k.upper(): v for k, v in jeeves_content.items()}
        request_id = normalized_input.get(DocEmbCt.REQUEST_ID, None)
        if request_id is None:
          msg = f"Warning! Request {i} must have a request id specified in `{DocEmbCt.REQUEST_ID}`."
          self.P(msg)
        # endif request_id provided

        # Check request type
        request_type = normalized_input.get(DocEmbCt.REQUEST_TYPE, DocEmbCt.DEFAULT_REQUEST_TYPE)
        if request_type not in DocEmbCt.REQUEST_TYPES:
          msg = f"Error! `{DocEmbCt.REQUEST_TYPE}` value must be one of {DocEmbCt.REQUEST_TYPES}. Received {request_type}."
          self.P(msg)
          processed_requests.append(self.processed_bad_request(msg, request_id=request_id))
          continue
        # endif request type is not valid

        # Check request params
        request_params = normalized_input.get(DocEmbCt.REQUEST_PARAMS, {})
        if not isinstance(request_params, dict) and request_type != DocEmbCt.LIST_CONTEXT:
          msg = f"Error! `{DocEmbCt.REQUEST_PARAMS}` value must be a dict. Received {type(request_params)}!"
          self.P(msg)
          processed_requests.append(self.processed_bad_request(msg, request_id=request_id))
          continue
        # endif request params is not a dict

        # Validate the request params
        is_bad_request, processed_request_params, msg = self.doc_embedding_validate_request_params(
          request_type=request_type, request_params=request_params
        )

        processed_requests.append({
          DocEmbCt.REQUEST_ID: request_id,
          DocEmbCt.REQUEST_TYPE: request_type if not is_bad_request else DocEmbCt.BAD_REQUEST,
          DocEmbCt.REQUEST_PARAMS: processed_request_params if not is_bad_request else {},
          DocEmbCt.ERROR_MESSAGE: msg,
          'PREDICT_KWARGS': predict_kwargs
        })
      # endfor each input
      return processed_requests, relevant_input_ids, cnt_total_inputs
  """END PREPROCESS OF REQUESTS"""

  """PROCESSING OF REQUESTS"""
  if True:
    def pooling(self, last_hidden, attn_mask):
      """
      Pool the last hidden states using the attention mask.
      Parameters
      ----------
      last_hidden : torch.Tensor (batch_size, seq_len, hidden_size) with the last hidden states
      attn_mask : torch.Tensor (batch_size, seq_len) with 0s for padding and 1s for real tokens

      Returns
      -------
      torch.Tensor (batch_size, hidden_size) with the pooled embeddings
      """
      return self.th.sum(last_hidden * attn_mask.unsqueeze(-1), dim=1) / self.th.sum(attn_mask, dim=1, keepdim=True)

    def embed_texts(self, texts):
      """
      Embed the texts using the model.
      Parameters
      ----------
      texts : str or list[str] - the text or the list of texts to be embedded

      Returns
      -------

      """
      self.P(f"Embedding {len(texts) if isinstance(texts, list) else 1} texts...")
      if not isinstance(texts, list):
        texts = [texts]
      # endif texts is not a list
      if self.cfg_max_batch_size is not None and len(texts) > self.cfg_max_batch_size:
        batches = [texts[i:i + self.cfg_max_batch_size] for i in range(0, len(texts), self.cfg_max_batch_size)]
      else:
        batches = [texts]
      # endif more texts than max batch size
      embeddings = []
      for batch in batches:
        with self.th.no_grad():
          input_dict = self.tokenizer(
            batch, padding=True, truncation=True, return_tensors='pt'
          )
          input_dict = {k: v.to(self.device) for k, v in input_dict.items()}
          outputs = self.model(**input_dict)
        # endwith no grad
        current_embeddings = self.pooling(outputs.last_hidden_state, input_dict['attention_mask'])
        current_embeddings = self.th.nn.functional.normalize(current_embeddings, p=2, dim=1)
        embeddings.append(current_embeddings.to('cpu'))
        self.th_utils.clear_cache()
      # endfor each batch
      return self.th.cat(embeddings, dim=0)

    def __add_docs(self, docs, context: str = None):
      """
      Add the documents to the context.
      Parameters
      ----------
      docs : list[str] - the list of documents
      context : str - the context name
      """
      context = self.__context_identifier(context)
      # endif context is None
      if context not in self.__dbs:
        self.P(f"Creating new context: {context}")
        self.__dbs[context] = HNSWVectorDB[NaeuralDoc](
          workspace=self.__db_cache_workspace(context)
        )
        self.__backup_contexts()
      # endif context not in dbs
      segments = self.__doc_splitter.split_documents(docs)
      segments_embeddings = self.embed_texts(segments)
      curr_size = self.__dbs[context].num_docs()['num_docs']
      lst_docs = [
        NaeuralDoc(text=segment, embedding=emb, idx=curr_size + i)
        for i, (segment, emb) in enumerate(zip(segments, segments_embeddings))
      ]
      # TODO: maybe check for duplicates
      self.P(f"Indexing {len(lst_docs)} documents in context '{context}'...")
      self.__dbs[context].index(inputs=DocList[NaeuralDoc](lst_docs))
      return

    def get_result_dict(self, request_id, docs=None, query=None, context_list=None, error_message=None, **kwargs):
      """
      Get the result dictionary.
      Parameters
      ----------
      request_id : str - the request id
      docs : list[str] - the document list
      query : str - the query
      context_list : list[str] - the list of available contexts
      error_message : str - the error message, in case of an error
      kwargs : dict - additional parameters

      Returns
      -------
      dict - the result dictionary
      """
      uppercase_kwargs = {k.upper(): v for k, v in kwargs.items()}
      return {
        DocEmbCt.REQUEST_ID: request_id,
        'DOCS': docs,
        DocEmbCt.QUERY: query,
        'CONTEXT_LIST': context_list,
        'MODEL_NAME': self.cfg_model_name,
        DocEmbCt.ERROR_MESSAGE: error_message,
        **uppercase_kwargs
      }

    def _predict(self, processed_batch):
      """
      Perform the prediction using the preprocessed requests.
      For details about the requests see the `_pre_process` method.
      Parameters
      ----------
      processed_batch: list of 3 elements:
        preprocessed_requests : list[dict] - the preprocessed requests
          - each dict must have the following keys:
            - REQUEST_ID : str - the request id
            - REQUEST_TYPE : str - the request type: QUERY, ADD_DOC, LIST_CONTEXT
            - REQUEST_PARAMS : dict - the request parameters - can vary depending on the request type
          - each dict can have the following keys(they are optional):
            - PREDICT_KWARGS(not used for the moment) : dict - the prediction kwargs,
            additional parameters for the prediction

        relevant_input_ids : list[int] - the list of relevant input ids
        cnt_total_inputs : int - the total number of inputs received

      Returns
      -------
      list[dict] - the predictions for each query or context query
        - each dict must have the following keys
          - REQUEST_ID : str - the request id
          - DOCS : list[str] - the requested documents, empty in case of ADD_DOC or LIST_CONTEXT
          - QUERY : str - the query, None if not a query
          - CONTEXT_LIST : list[str] - the list of available contexts in case of LIST_CONTEXT or None
          - MODEL_NAME : str - the model name
          - ERROR_MESSAGE : str - the error message, if any
          - additional keys can be added
      """
      preprocessed_requests, relevant_input_ids, cnt_total_inputs = processed_batch
      results = []
      request_ids = [req[DocEmbCt.REQUEST_ID] for req in preprocessed_requests]
      self.D(f'Processing {len(preprocessed_requests)} requests: {[request_ids]}')
      for i, req in enumerate(preprocessed_requests):
        req_id = req[DocEmbCt.REQUEST_ID]
        req_type = req[DocEmbCt.REQUEST_TYPE]
        self.D(f'Processing request {i + 1}/{len(preprocessed_requests)}: {req_id}|{req_type}')
        if req_type == DocEmbCt.LIST_CONTEXT:
          results.append(
            self.get_result_dict(request_id=req_id, context_list=list(self.__dbs.keys()))
          )
        elif req_type == DocEmbCt.ADD_DOC:
          req_params = req[DocEmbCt.REQUEST_PARAMS]
          context_id = req_params.get(DocEmbCt.CONTEXT_ID, None)
          docs = req_params.get('docs') or []
          # TODO: with this implementation a context may be influenced by multiple sets of users.
          #  This can lead to a context that is not representative for any of the users.
          self.P(f"Processing 'ADD_DOC' for context '{context_id}'")
          self.__add_docs(docs, context_id)
          results.append(self.get_result_dict(request_id=req_id))
        elif req_type == DocEmbCt.QUERY:
          # TODO: maybe support the following query:
          #  query + temporary context => the context will not be saved, but will be
          #  segmented and used for the query.
          req_params = req[DocEmbCt.REQUEST_PARAMS]
          query = req_params[DocEmbCt.QUERY]
          context = req_params.get(DocEmbCt.CONTEXT_ID, None)
          context = self.__context_identifier(context)
          k = req_params.get(DocEmbCt.K, DEFAULT_NUMBER_OF_RESULTS)
          self.P(f"Processing query {query} in context {context} with k={k}")
          # In case the context is not available, return an error message.
          if context not in self.__dbs:
            self.P(f"Context {context} not found.")
            results.append(
              self.get_result_dict(request_id=req_id, error_message=f"Error! Context {context} not found.")
            )
            continue
          # endif context not in dbs
          # Embed the query.
          query_embedding = self.embed_texts(query)
          query_doc = NaeuralDoc(text=query, embedding=query_embedding, idx=-1)
          # Search for the closest documents.
          self.P(f"Searching for the closest {k} documents to the query in context '{context}'...")
          search_results = self.__dbs[context].search(
            inputs=DocList[NaeuralDoc]([query_doc]), limit=k
          )[0]
          self.P(f"Search results: {search_results}")
          matches, scores = search_results.matches, search_results.scores
          matches_with_scores = [
            (match, score) for match, score in zip(matches, scores)
          ]
          matches_ordered_by_idx = sorted(matches_with_scores, key=lambda x: x[0].idx)
          # Sort the results by the index.
          result_texts = [
            res[0].text for res in matches_ordered_by_idx
          ]
          self.P(f"Result texts: {result_texts}")
          results.append(
            self.get_result_dict(request_id=req_id, docs=result_texts, query=query)
          )
        elif req_type == DocEmbCt.BAD_REQUEST:
          err_msg = req[DocEmbCt.ERROR_MESSAGE]
          results.append(
            self.get_result_dict(request_id=req_id, error_message=err_msg)
          )
        self.D(f'Processed request {i + 1}/{len(preprocessed_requests)}: {results[-1]}')
        # endif request type
      # endfor each preprocessed request
      return results, relevant_input_ids, cnt_total_inputs
  """END PROCESSING OF REQUESTS"""

  def _post_process(self, preds_batch):
    preds_batch, relevant_input_ids, cnt_total_inputs = preds_batch
    self.P(f"Post-processing {len(preds_batch)} results out of {cnt_total_inputs} total inputs.")
    final_result = []
    current_text_idx = 0
    for i in range(cnt_total_inputs):
      if i in relevant_input_ids:
        final_result.append(preds_batch[current_text_idx])
        current_text_idx += 1
      else:
        final_result.append({
          "IS_VALID": False,
          "MODEL_NAME": self.cfg_model_name,
        })
    # endfor each total input
    return final_result
# endclass BaseDocEmbServing

