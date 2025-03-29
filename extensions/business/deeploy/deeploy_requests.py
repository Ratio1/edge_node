"""
xamples:

Create request nonce 2025-03-28 10:36:37:
{
  "request": {
    "app_name": "SOME_APP_NAME",
    "plugin_signature": "SOME_PLUGIN_01",
    "nonce": "0x195dc533d7b",
    "target_nodes": [
      "0xai_Amfnbt3N-qg2-qGtywZIPQBTVlAnoADVRmSAsdDhlQ-6",
      "0xai_Amfnbt3N-qg2-qGtywZIPQBTVlAnoADVRmSAsdDhlQ-7"
    ],
    "target_nodes_count": 0,
    "app_params": {
      "IMAGE": "repo/image:tag",
      "REGISTRY": "docker.io",
      "USERNAME": "user",
      "PASSWORD": "password",
      "PORT": 5000,
      "OTHER_PARAM1": "value1",
      "OTHER_PARAM2": "value2",
      "OTHER_PARAM3": "value3",
      "OTHER_PARAM4": "value4",
      "OTHER_PARAM5": "value5",
      "ENV": {
        "ENV1": "value1",
        "ENV2": "value2",
        "ENV3": "value3",
        "ENV4": "value4"
      }
    },
    "EE_ETH_SIGN": "0x8350f9600dc872d2d37d25d8cbe672dd2d1ee23cc80366a9d3b0f30d2f3249872fac116db5aee6d88911a180fae6c4e7ec0e5750de320221b7a14e1cb6ad8ad91c",
    "EE_ETH_SENDER": "0x168f051A021E0cCaD836DA6968C09Fc5F0E92A06"
  }
}

Get apps request nonce 2025-03-28 10:36:37:
{
  "request": {
    "nonce": "0x195dc533d7b",
    "EE_ETH_SIGN": "0x35aef39f6e5cb32cefaecd5d852fa786e855e1d8bd4bacf78cc286103bf9bdb3600785710306ff72e2bc4bac76b99ca3ab920e16ca898c0692fbea0a2c1f043a1c",
    "EE_ETH_SENDER": "0x168f051A021E0cCaD836DA6968C09Fc5F0E92A06"
  }
}

Delete request nonce 2025-03-28 10:36:37:
{
  "request": {
    "app_name": "SOME_APP_NAME",
    "target_nodes": [
      "0xai_node_1",
      "0xai_node_2"
    ],
    "nonce": "0x195dc533d7b",
    "EE_ETH_SIGN": "0xfcab3eb3133edc1b35ec7866279160302635ab3b0159a7ec10c5ed0966bc30a634180b024ee477368ee0f413a581d122a070f9a5473922e9aa487c9a624270251c",
    "EE_ETH_SENDER": "0x168f051A021E0cCaD836DA6968C09Fc5F0E92A06"
  }
}

"""
from time import time
from uuid import uuid4

DEEPLOY_CREATE_REQUEST = {
  "app_name" : "app_" + str(uuid4())[:8], 
  "plugin_signature" : "SOME_PLUGIN_01",
  "nonce" : hex(int(time() * 1000)), # recoverable via int(nonce, 16)
  "target_nodes" : [
    "0xai_node_1",
    "0xai_node_2",
  ],
  "target_nodes_count" : 0,
  "app_params" : {
    "IMAGE" : "repo/image:tag",
    "REGISTRY" : "docker.io",
    "USERNAME" : "user",
    "PASSWORD" : "password",
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
  "pipeline_input_type"  : "void",
  "pipeline_input_uri" : None,
  }    
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
