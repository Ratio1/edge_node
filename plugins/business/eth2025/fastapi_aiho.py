from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin


_CONFIG = {
  **FastApiWebAppPlugin.CONFIG,
  'ASSETS' : 'people_counting',
  'OBJECT_TYPE' : [ 'person' ],
  'DETECTOR_PROCESS_DELAY' : 0.2,
  'STATUS_UPDATE_INTERVAL' : 2,
  'VALIDATION_RULES': {
    **FastApiWebAppPlugin.CONFIG['VALIDATION_RULES'],
  },
}

class FastapiAihoPlugin(FastApiWebAppPlugin):
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(FastapiAihoPlugin, self).__init__(**kwargs)
    return

  def get_jinja_template_args(self) -> dict:
    return {
      **super(FastapiAihoPlugin, self).get_jinja_template_args()
    }

  def on_init(self):
    super(FastapiAihoPlugin, self).on_init()
    self.P("Running post-init setup")
    # Dict with url -> answer, done
    self.request_data = {}
    self._home_security_events = {}
    self._predictive_maintenance_events = {}
    self._predictive_maintenance_measurements = {}
    self._property_documents = {}
    self._last_home_security_ping = 0
    self._last_predictive_maintenance_ping = 0
    self.my_id = f'r1:aiho{self.ee_id}'
    return
  
  # HOME SAFETY

  @FastApiWebAppPlugin.endpoint(method="post")
  def new_home_security_event(self, propertyId: int, base64img: str, isAlert: bool):
    self.P(f"new_home_security_event")
    self._last_home_security_ping = int(self.time())
    if propertyId not in self._home_security_events:
        self._home_security_events[propertyId] = []
    if isAlert:
        self._home_security_events[propertyId].append({
            "timestamp": int(self.time()),
            "base64img": base64img,
        })
    return {
      "status": "ok",
      "length": len(self._home_security_events[propertyId]),
    }
  
  @FastApiWebAppPlugin.endpoint
  def get_last_home_security_event(self, propertyId: int):
    self.P(f"get_last_home_security_event")
    if propertyId not in self._home_security_events:
      self._home_security_events[propertyId] = []
    if len(self._home_security_events[propertyId]) == 0:
      return {
        "status": "no_event",
        "event": None,
      }
    event = self._home_security_events[propertyId][-1]
    return {
      "status": "ok",
      "event": event,
      "last_home_security_ping": self._last_home_security_ping,
    }
  
  @FastApiWebAppPlugin.endpoint
  def get_home_security_events(self, propertyId: int, nEvents: int):
    self.P(f"get_last_home_security_event")
    if propertyId not in self._home_security_events:
      self._home_security_events[propertyId] = []
    if nEvents > len(self._home_security_events[propertyId]):
      nEvents = len(self._home_security_events[propertyId])
    return {
      "status": "ok",
      "events": self._home_security_events[propertyId][-nEvents:],
      "last_home_security_ping": self._last_home_security_ping,
    }
  
  
  # PREDICTIVE MAINTENANCE

  @FastApiWebAppPlugin.endpoint(method="post")
  def new_predictive_maintenance_event(self, propertyId: int, temperature: int, humidity: int, reason_key: str):
    self.P(f"new_predictive_maintenance_event")
    self._last_predictive_maintenance_ping = int(self.time())
    if propertyId not in self._predictive_maintenance_events:
        self._predictive_maintenance_events[propertyId] = []
    if reason_key == "temperature":
        self._predictive_maintenance_events[propertyId].append({
            "timestamp": int(self.time()),
            "temperature": temperature,
        })
    elif reason_key == "humidity":
        self._predictive_maintenance_events[propertyId].append({
            "timestamp": int(self.time()),
            "humidity": humidity,
        })
    elif reason_key == "both":
        self._predictive_maintenance_events[propertyId].append({
            "timestamp": int(self.time()),
            "temperature": temperature,
        })
        self._predictive_maintenance_events[propertyId].append({
            "timestamp": int(self.time()),
            "humidity": humidity,
        })
    return {
      "status": "ok",
    }

  @FastApiWebAppPlugin.endpoint(method="post")
  def new_predictive_maintenance_measurements(self, propertyId: int, measurements: list[dict]):
    self.P(f"new_predictive_maintenance_measurements")
    self._last_predictive_maintenance_ping = int(self.time())
    if propertyId not in self._predictive_maintenance_measurements:
        self._predictive_maintenance_measurements[propertyId] = []
    self._predictive_maintenance_events[propertyId] = measurements
    return {
      "status": "ok",
    }
  
  @FastApiWebAppPlugin.endpoint
  def get_predictive_maintenance_events(self, propertyId: int, nEvents: int):
    self.P(f"get_predictive_maintenance_events")
    if propertyId not in self._predictive_maintenance_events:
      self._predictive_maintenance_events[propertyId] = []
    if nEvents > len(self._predictive_maintenance_events[propertyId]):
      nEvents = len(self._predictive_maintenance_events[propertyId])
    return {
      "status": "ok",
      "events": self._predictive_maintenance_events[propertyId][-nEvents:],
    }
  
  @FastApiWebAppPlugin.endpoint
  def get_predictive_maintenance_measurements(self, propertyId: int):
    self.P(f"get_predictive_maintenance_measurements")
    if propertyId not in self._predictive_maintenance_measurements:
      self._predictive_maintenance_measurements[propertyId] = []
    return {
      "status": "ok",
      "measurements": self._predictive_maintenance_measurements[propertyId],
    }
  
  # R1FS

  @FastApiWebAppPlugin.endpoint(method="post")
  def new_property_document(self, propertyId: int, fileName:str, base64document: str):
    self.P(f"new_property_document")
    if propertyId not in self._property_documents:
      self._property_documents[propertyId] = []
    fn = self.diskapi_save_bytes_to_output(data=base64document, filename=fileName, from_base64=True)
    self.P(f"new_property_document: {fn}")
    cid = self.r1fs.add_file(fn)
    self.P(f"new_property_document cid : {cid}")
    self._property_documents[propertyId].append({
      "timestamp": int(self.time()),
      "fileName": fileName,
      "cid": cid,
    })
    return {
      "status": "ok",
    }
  
  @FastApiWebAppPlugin.endpoint
  def get_property_documents_list(self, propertyId: int):
    self.P(f"get_property_documents_list")
    if propertyId not in self._property_documents:
      self._property_documents[propertyId] = []
    return {
      "status": "ok",
      "documents": self._property_documents[propertyId],
    }
  
  @FastApiWebAppPlugin.endpoint
  def get_property_document(self, propertyId: int, cid: str):
    self.P(f"get_property_document")
    if propertyId not in self._property_documents:
      self._property_documents[propertyId] = []
    for doc in self._property_documents[propertyId]:
      if doc["cid"] == cid:
        fn = self.r1fs.get_file(cid)
        self.P(f"get_property_document: {fn}")
        if fn is not None:
          base64document = self.diskapi_load_r1fs_file(filename=fn, to_base64=True)
          return {
            "status": "ok",
            "document": base64document,
          }
        else:
          self.P(f"get_property_document: file not found")
          return {
            "status": "error",
            "message": "File not found",
          }
    return {
      "status": "error",
      "message": "Document not found",
    }
