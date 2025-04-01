"""
Examples:

- plugin_signature: "A_SIMPLE_PLUGIN"
- pipeline_input_type: "ExampleDatastream"




"""
from time import time
from uuid import uuid4

DEEPLOY_CREATE_REQUEST = {
  "app_name" : "some_app_name", 
  "plugin_signature" : "SOME_PLUGIN_01",
  "nonce" : hex(int(time() * 1000)), # recoverable via int(nonce, 16)
  "target_nodes" : [
    "0xai_node_1",
    "0xai_node_2",
  ],
  "target_nodes_count" : 0,
  "app_params" : {
    "IMAGE" : "repo/image:tag",
    "CR" : "docker.io",
    "CR_USERNAME" : "user",
    "CR_PASSWORD" : "password",
    "PORT" : 5000,
    "OTHER_PARAM1" : "value1",
    "OTHER_PARAM2" : "value2",
    "OTHER_PARAM3" : "value3",
    "OTHER_PARAM4" : "value4",
    "OTHER_PARAM5" : "value5",
    "ENV" : {
      "ENV1" : "value1",
      "ENV2" : "value2",
      "ENV3" : "value3",
      "ENV4" : "value4",
    },
  },
  "pipeline_input_type"  : "void",
  "pipeline_input_uri" : None,
}


DEEPLOY_GET_APPS_REQUEST = {
  "nonce" : hex(int(time() * 1000)), # recoverable via int(nonce, 16)
}

DEEPLOY_DELETE_REQUEST = {
  "app_name" : "target_app_name",
  "target_nodes" : [
    "0xai_target_node_1",
    "0xai_target_node_2",
  ],
  "nonce" : hex(int(time() * 1000)), # recoverable via int(nonce, 16)
}  
