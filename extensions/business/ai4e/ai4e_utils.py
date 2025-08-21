# from ratio1 import Session, Pipeline, Instance
from datetime import datetime
import numpy as np


def job_data_to_id(node_id, pipeline, signature, instance):
  return instance


def maybe_strip(s):
  if isinstance(s, str):
    return s.strip()
  return s


def classes_dict_to_msg(classes):
  return [{'name': maybe_strip(k), 'description': v} for k, v in classes.items()]


def classes_msg_to_dict(classes):
  return {maybe_strip(c['name']): c['description'] for c in classes}


def process_data_sources(data_sources):
  return [
    {
      k.upper(): v
      for k, v in data_dict.items()
    } for data_dict in data_sources
  ]


def get_job_config(
  job_id: str, job_config: dict, creation_date: str
):
  name = job_config.get('name')
  desc = job_config.get('description')
  data_sources = process_data_sources(job_config.get('dataSources'))
  target = job_config.get('target')
  classes = job_config.get('classes')
  rewards = job_config.get('rewards')
  dataset = job_config.get('dataset')
  plugin_config = {
    "SIGNATURE": "AI4E_END_TO_END_TRAINING",
    "INSTANCES": []
  }
  instance_config = {
    "INSTANCE_ID": job_id,
    "OBJECTIVE_NAME": name,
    "GENERAL_DETECTOR_OBJECT_TYPE": target,
    "CLASSES": classes_msg_to_dict(classes) if classes is not None else {},
    "DESCRIPTION": desc,
    "DATA": {
      "SOURCES": data_sources
    },
    "REWARDS": rewards,
    "DATASET": dataset,
    "CREATION_DATE": creation_date,
    "AUTO_DEPLOY": None
  }
  plugin_config["INSTANCES"].append(instance_config)
  return plugin_config


class Job:
  def __init__(self, owner, job_id: str, node_id: str, pipeline: str, signature: str, instance: str):
    self.owner = owner
    # self.session = session
    self.job_id = job_id
    # TODO: instead of single values for instance_id and the rest, use a dict to
    # have a set of properties for each subtask(each signature)
    self.instance_id = instance
    self.node_id = node_id
    self.pipeline = pipeline
    self.signature = signature

    self.objective_name = None
    self.description = None
    self.data_sources = []
    self.target = None
    self.classes = {}
    self.rewards = {}
    self.dataset = {}
    self.creation_date = None
    self.creation_date_str = None
    self.job_status = None
    self.final_ds_status = None

    self.data = {}
    self.crop_status = {
      'total_stats': {},
      'increment_history': [],
      'speed': 0,
      'last_duration': 0
    }
    self.label_status = {
      'total_files_voted': 0,
      'total_files_decided': 0,
      'voted_history': [],
      'decided_history': [],
      'decided_stats': {}
    }
    self.train_status = {
      'status': None,
      'remaining': 0,
      'elapsed': 0,
      'best': None,
      'current_grid_iteration': 0,
      'total_grid_iterations': 0,
    }
    self.train_meta = {}
    self.train_final = {}
    self.train_status_full_payload = None
    self.started_deploying = False
    self.deployed = False
    return

  def get_persistence_data(self):
    return {
      'job_id': self.job_id,
      'node_id': self.node_id,
      'pipeline': self.pipeline,
      'signature': self.signature,
      'instance_id': self.instance_id,

      'objective_name': self.objective_name,
      'description': self.description,
      'data_sources': self.data_sources,
      'target': self.target,
      'classes': self.classes,
      'rewards': self.rewards,
      'dataset': self.dataset,
      'creation_date': self.creation_date,
      'creation_date_str': self.creation_date_str,
      'job_status': self.job_status,
      'final_ds_status': self.final_ds_status,

      'crop_status': self.crop_status,
      'label_status': self.label_status,
      'train_status': self.train_status,
      'train_meta': self.train_meta,
      'train_final': self.train_final,

      'started_deploying': self.started_deploying,
      'deployed': self.deployed
    }

  def load_persistence_data(self, data):
    self.job_id = data.get('job_id', self.job_id)
    self.node_id = data.get('node_id', self.node_id)
    self.pipeline = data.get('pipeline', self.pipeline)
    self.signature = data.get('signature', self.signature)
    self.instance_id = data.get('instance_id', self.instance_id)

    self.objective_name = data.get('objective_name', self.objective_name)
    self.description = data.get('description', self.description)
    self.data_sources = data.get('data_sources', self.data_sources)
    self.target = data.get('target', self.target)
    self.classes = data.get('classes', self.classes)
    self.rewards = data.get('rewards', self.rewards)
    self.dataset = data.get('dataset', self.dataset)
    self.creation_date = data.get('creation_date', self.creation_date)
    self.creation_date_str = data.get('creation_date_str', self.creation_date_str)
    self.job_status = data.get('job_status', self.job_status)
    self.final_ds_status = data.get('final_ds_status', self.final_ds_status)

    self.crop_status = data.get('crop_status', self.crop_status)
    self.label_status = data.get('label_status', self.label_status)
    self.train_status = data.get('train_status', self.train_status)
    self.train_meta = data.get('train_meta', self.train_meta)
    self.train_final = data.get('train_final', self.train_final)

    self.started_deploying = data.get('started_deploying', self.started_deploying)
    self.deployed = data.get('deployed', self.deployed)
    return

  def maybe_update_data(self, data: dict, pipeline: str, signature: str):
    if data.get('IS_FINAL_DATASET_STATUS', False):
      self.final_ds_status = data.get('UPLOADED', self.final_ds_status)
      return
    if not data.get('IS_STATUS', False):
      return
    self.pipeline = pipeline
    self.signature = signature

    self.data = data
    self.objective_name = data.get('OBJECTIVE_NAME', self.objective_name)
    self.description = data.get('DESCRIPTION', self.description)
    self.data_sources = data.get('DATA_SOURCES', self.data_sources)
    self.target = data.get('TARGET', self.target)
    self.rewards = data.get('REWARDS', self.rewards)
    self.dataset = data.get('DATASET', self.dataset)
    cd_str = data.get('CREATION_DATE', self.creation_date_str)
    self.creation_date_str = cd_str
    cd_datetime = datetime.strptime(cd_str[:-6], '%Y%m%d%H%M%S') if cd_str is not None else None
    self.creation_date = int(cd_datetime.timestamp()) if cd_datetime is not None else None
    self.classes = data.get('CLASSES', self.classes)
    if self.classes is not None:
      self.classes = {maybe_strip(k): v for k, v in self.classes.items()}
    # endif classes
    self.job_status = data.get('JOB_STATUS', self.job_status)

    self.crop_status['total_stats'] = data.get('COUNTS', self.crop_status['total_stats'])
    last_increment = data.get('CROP_INCREMENT')
    if last_increment is not None:
      self.crop_status['increment_history'].append(last_increment)
    self.crop_status['speed'] = data.get('CROP_SPEED', self.crop_status['speed'])
    self.crop_status['last_duration'] = data.get('DURATION')

    if 'TOTAL_FILES_VOTED' in data.keys():
      self.label_status['total_files_voted'] = data.get('TOTAL_FILES_VOTED', self.label_status['total_files_voted'])
      self.label_status['total_files_decided'] = data.get('TOTAL_FILES_DECIDED', self.label_status['total_files_decided'])
      self.label_status['decided_stats'] = data.get('DECIDED_STATS', self.label_status['decided_stats'])
      self.label_status['voted_history'].append(self.label_status['total_files_voted'])
      self.label_status['decided_history'].append(self.label_status['total_files_decided'])
    # endif status for labels

    if signature.lower() in AI4E_CONSTANTS.TRAINING_PLUGIN_SIGNATURES:
      self.train_status_full_payload = data
    if 'TRAIN_STATUS' in data.keys():
      full_train_data = data.get('TRAIN_STATUS', None)
      if not isinstance(full_train_data, dict):
        if self.owner.cfg_debug_web_app:
          self.owner.P(f"`TRAIN_STATUS` is not a dict: {full_train_data}")
        return
      self.train_status['status'] = data.get('JOB_STATUS', self.train_status['status'])
      train_data = full_train_data.get('STATUS', None)
      if not isinstance(train_data, dict):
        if self.owner.cfg_debug_web_app:
          self.owner.P(f"`TRAIN_STATUS[`STATUS`]` is not a dict: {train_data}")
        return
      self.train_status['remaining'] = train_data.get('REMAINING', self.train_status['remaining'])
      self.train_status['elapsed'] = train_data.get('ELAPSED', self.train_status['elapsed'])

      train_meta_data = full_train_data.get('METADATA')
      if train_meta_data is not None:
        target_class = train_meta_data.get('FIRST_STAGE_TARGET_CLASS')
        self.train_meta = {
          'OBJECT_TYPE': target_class if isinstance(target_class, list) else [target_class],
          'SECOND_STAGE_DETECTOR_CLASSES': list(train_meta_data['CLASSES'].keys()),
          'MODEL_INSTANCE_ID': train_meta_data['MODEL_NAME']
        }
      # if train metadata present
      best_score = self.train_status['best']
      if train_data.get('BEST') is not None:
        best_score = train_data['BEST'].get('best_score')
      self.train_status['best'] = best_score
      self.train_status['current_grid_iteration'] = train_data.get('GRID_ITER', self.train_status['current_grid_iteration'])
      self.train_status['total_grid_iterations'] = train_data.get('NR_ALL_GRID_ITER', self.train_status['total_grid_iterations'])
      if 'TRAIN_FINAL' in data.keys():
        self.train_final = data.get('TRAIN_FINAL', self.train_final)
      # endif training finished

    # endif status for training

    return

  def get_data(self):
    return self.data

  def get_details(self):
    return {
      'name': self.objective_name,
      'description': self.description,
      'dataSources': self.data_sources,
      'target': self.target,
      'classes': classes_dict_to_msg(self.classes),
      'rewards': self.rewards,
      'dataset': self.dataset,
      'creationDate': self.creation_date,
      'creationDateStr': self.creation_date_str
    }

  def get_job_status(self):
    # if self.deployed:
    #   return "Deployed"
    # if self.started_deploying:
    #   return "Deploying"
    if self.train_status.get('status') is not None:
      return self.train_status['status']
    if self.final_ds_status is not None:
      return "Ready for training"
    return self.job_status

  def to_msg(self):
    return {
      'id': self.job_id,
      'config': self.get_details(),
      'status': self.get_job_status(),
      'creationDate': self.creation_date,
    }

  def get_status(self):
    return {
      'status': self.get_job_status(),
      'counts': self.crop_status['total_stats'],
      'job': self.to_msg(),
      'crop': {
        'speed': self.crop_status['speed'],
        'history': self.crop_status['increment_history'],
        'duration': self.crop_status['last_duration'],
      },
    }

  def get_labeling_status(self):
    return {
      'history': [
        self.label_status['voted_history'],
        self.label_status['decided_history']
      ],
      'stats': self.label_status['decided_stats']
    }

  def get_train_status(self):
    if self.train_status.get('status') is None:
      return {}
    elapsed = self.train_status.get('elapsed')
    remaining = self.train_status.get('remaining')
    if elapsed is None or remaining is None:
      return {}
    total = elapsed + remaining
    progress = 0
    if total > 0:
      progress = elapsed / total
    return {
      'remaining': remaining,
      'elapsed': elapsed,
      'score': self.train_status['best'],
      'progress': progress,
      'currentGridIteration': self.train_status['current_grid_iteration'],
      'totalGridIterations': self.train_status['total_grid_iterations'],
      # 'full_last_payload': self.train_status_full_payload
    }

  # def __get_pipeline_and_instance(self, node=None, pipeline=None, signature=None, instance_id=None):
  #   node = node or self.node_id
  #   active_pipelines = self.session.get_active_pipelines(node=node)
  #   if active_pipelines is None:
  #     return None, None, f"Node_ID {node} not found"
  #   pipeline = pipeline or self.pipeline
  #   curr_pipeline = self.session.attach_to_pipeline(node=node, name=pipeline)
  #   if curr_pipeline is None:
  #     return None, None, f"Pipeline {pipeline} not found on {node}"
  #   signature = signature or self.signature
  #   instance_id = instance_id or self.instance_id
  #   curr_instance = curr_pipeline.attach_to_plugin_instance(
  #     signature=signature,
  #     instance_id=instance_id
  #   )
  #   if curr_instance is None:
  #     return curr_pipeline, None, f"Instance {instance_id} of {signature} not found on {pipeline}"
  #   return curr_pipeline, curr_instance, ""

  def send_instance_command(self, node=None, pipeline=None, signature=None, instance_id=None, **kwargs):
    node = node or self.node_id
    pipeline = pipeline or self.pipeline
    signature = signature or self.signature
    instance_id = instance_id or self.instance_id
    command_kwargs = {
      k.upper(): v
      for k, v in kwargs.items()
    }
    self.owner.cmdapi_send_instance_command(
      pipeline=pipeline, signature=signature, instance_id=instance_id,
      node_address=node, instance_command=command_kwargs
    )
    return True, "Command sent successfully"
    #
    #
    # pipeline, instance, error = self.__get_pipeline_and_instance(
    #   node=node, pipeline=pipeline, signature=signature, instance_id=instance_id
    # )
    # if error != "":
    #   return False, error
    # command_kwargs = {
    #   k.upper(): v
    #   for k, v in kwargs.items()
    # }
    # instance.send_instance_command(command_kwargs)
    # return True, "Command sent successfully"

  def send_instance_update(self, config: dict, node=None, pipeline=None, signature=None, instance_id=None):
    node = node or self.node_id
    pipeline = pipeline or self.pipeline
    signature = signature or self.signature
    instance_id = instance_id or self.instance_id
    self.owner.cmdapi_update_instance_config(
      pipeline=pipeline, signature=signature, instance_id=instance_id,
      node_address=node, instance_config=config
    )


    # pipeline, instance, error = self.__get_pipeline_and_instance(
    #   node=node, pipeline=pipeline, signature=signature, instance_id=instance_id
    # )
    # if error != "":
    #   return False, error
    # instance.update_instance_config(config)
    # pipeline.deploy()
    return True, "Config updated successfully"

  def stop_acquisition(self):
    success, err_msg = self.send_instance_update({"FORCE_TERMINATE_COLLECT": True})
    if not success:
      err_msg = f"Error for {self.job_id} - {self.pipeline} - {self.instance_id}:\n{err_msg}"
      return False, err_msg
    return True, "Successfully stopped acquisition for job"

  def publish_job(self, classes: list[dict], rewards: dict):
    update_config = {
      'CLASSES': classes_msg_to_dict(classes),
      'REWARDS': rewards,
    }
    e2e_update_config = {
      'CLASSES': update_config['CLASSES'],
    }
    success, err_msg = self.send_instance_update(update_config)
    if not success:
      err_msg = f"Error for {self.job_id} - {self.pipeline} - {self.instance_id}:\n{err_msg}"
      return False, err_msg
    success, err_msg = self.send_instance_update(
      e2e_update_config,
      pipeline=f'cte2e_{self.job_id}',
      signature='AI4E_END_TO_END_TRAINING'
    )
    if not success:
      err_msg = f"Error for {self.job_id} - {self.pipeline} - {self.instance_id}:\n{err_msg}"
      return False, err_msg
    return self.send_instance_command(start_voting=True)

  def send_vote(self, filename: str, label: str):
    datapoint = {
      'FILENAME': filename,
      'LABEL': label
    }
    return self.send_instance_command(datapoint=datapoint, worker_id='default')

  def stop_labeling(self):
    return self.send_instance_command(finish_labeling=True)

  def publish_labels(self):
    return self.send_instance_command(publish=True)

  def start_train(self, body: dict):
    self.owner.P(f'Starting training for {self.job_id} on {self.node_id}...')
    success, err_msg = self.send_instance_update(
      config={
        'START_TRAINING': True,
        'TRAINING': {
          # TODO: this should eventually change to architecture or something more generic than classifier
          'MODEL_ARCHITECTURE': body.get('classifier', 'BASIC_CLASSIFIER'),
        },
        "TRAINING_REWARDS": {
          'budget': body.get('budget', 0),
        }
      },
      node=self.node_id,
      pipeline=f'cte2e_{self.job_id}',
      signature='AI4E_END_TO_END_TRAINING',
      instance_id=self.job_id,
    )
    if not success:
      err_msg = f"Error at train start for {self.job_id} on {self.node_id}:\n{err_msg}"
      return False, err_msg
    return True, "Training started"

  def deploy_configs(self, lst_allowed, deploy_ngrok_edge_label):
    """
    2 pipelines will be deployed:
      1. One custom detection pipeline to run the freshly obtained custom model
      2. One fastapi pipeline on which the user will be able to interact with the
      previously mentioned pipeline.
    Parameters
    ----------
    lst_allowed: list
      Nodes where the above-mentioned pipelines can be deployed.

    deploy_ngrok_edge_label: str
      The label of the ngrok edge node where the pipelines will be deployed.

    Returns
    -------

    """
    # chosen_node = np.random.choice(lst_allowed)
    chosen_node = self.owner.e2_addr
    # START DETECTION PIPELINE
    instance_config = {
      "AI_ENGINE": "custom_second_stage_detector",
      "OBJECT_TYPE": self.train_meta['OBJECT_TYPE'],
      'SECOND_STAGE_DETECTOR_CLASSES': self.train_meta['SECOND_STAGE_DETECTOR_CLASSES'],
      'STARTUP_AI_ENGINE_PARAMS': {
        'CUSTOM_DOWNLOADABLE_MODEL_URL': self.train_final['INFERENCE_CONFIG_URI']['URL'],
        'MODEL_INSTANCE_ID': self.train_meta['MODEL_INSTANCE_ID']
      },
      'DESCRIPTION': self.description,
      'OBJECTIVE_NAME': self.objective_name,
      "INSTANCE_ID": self.job_id,
    }
    inference_pipeline_config = {
      "TYPE": "ON_DEMAND_INPUT",
      "NAME": f"deploy_{self.job_id}",
      "PLUGINS": [
        {
          "INSTANCES": [
            instance_config
          ],
          "SIGNATURE": "ai4e_custom_inference_agent",
        }
      ]
    }
    self.owner.cmadpi_start_pipeline(
      config=inference_pipeline_config,
      node_address=chosen_node,
    )
    # END DETECTION PIPELINE
    # START FASTAPI PIPELINE
    fastapi_instance_id = "AI4EveryoneDeploys"
    fastapi_instance_config = {
      "RESPONSE_FORMAT": self.owner.cfg_response_format,
      "NGROK_EDGE_LABEL": deploy_ngrok_edge_label,
      "INSTANCE_ID": fastapi_instance_id,
    }
    fastapi_pipeline_name = f"AI4EveryoneDeploys"
    fastapi_signature = "AI4E_DEPLOY"
    fastapi_pipeline_config = {
      "NAME": fastapi_pipeline_name,
      "TYPE": "VOID",  # Change to custom NetworkListener
      "PLUGINS": [
        {
          "INSTANCES": [
            {
              fastapi_instance_config
            }
          ],
          "SIGNATURE": fastapi_signature,
        }
      ]
    }
    self.owner.cmadpi_start_pipeline(
      config=fastapi_pipeline_config,
      node_address=chosen_node,
    )
    self.send_instance_command(
      node=chosen_node,
      pipeline=fastapi_pipeline_name,
      signature=fastapi_signature,
      instance_id=fastapi_instance_id,
      command='REGISTER',
      command_params={
        'CONFIG': instance_config
      }
    )
    # END FASTAPI PIPELINE
    return

  def deploy_job(self, body):
    if self.deployed:
      return True, "Job already deployed"
    self.started_deploying = True
    # lst_allowed = self.session.get_allowed_nodes()
    lst_allowed = self.owner.netmon.accessible_nodes()
    self.owner.P(f"Allowed nodes: {lst_allowed}")
    if len(lst_allowed) == 0:
      self.started_deploying = False
      return False, "No node available at the moment."
    self.deploy_configs(
      lst_allowed=lst_allowed,
      deploy_ngrok_edge_label=self.owner.cfg_deploy_ngrok_edge_label,
    )

    self.started_deploying = False
    self.deployed = True
    return True, "Job deployed"
# endclass Job


class AI4E_CONSTANTS:
  TRAINING_PLUGIN_SIGNATURES = [
    "second_stage_training_process", "general_training_process",
  ]
  RELEVANT_PLUGIN_SIGNATURES = [
    "ai4e_crop_data", "ai4e_label_data",
    "second_stage_training_process", "general_training_process",
    "minio_upload_dataset"
  ]
  AVAILABLE_DATA_SOURCES = ['VideoStream', 'VideoFile']
  AVAILABLE_ARCHITECTURES = {
    'BASIC_CLASSIFIER': "Small architecture. The training will be faster, but the accuracy may be lower.",
    'ADVANCED_CLASSIFIER': "More complex architecture. The training will be slower, but the accuracy may be higher.",
  }
  FIRST_STAGE_CLASSES = [
  "person",
  "bicycle",
  "car",
  "motorcycle",
  "airplane",
  "bus",
  "train",
  "truck",
  "boat",
  "traffic light",
  "fire hydrant",
  "stop sign",
  "parking meter",
  "bench",
  "bird",
  "cat",
  "dog",
  "horse",
  "sheep",
  "cow",
  "elephant",
  "bear",
  "zebra",
  "giraffe",
  "backpack",
  "umbrella",
  "handbag",
  "tie",
  "suitcase",
  "frisbee",
  "skis",
  "snowboard",
  "sports ball",
  "kite",
  "baseball bat",
  "baseball glove",
  "skateboard",
  "surfboard",
  "tennis racket",
  "bottle",
  "wine glass",
  "cup",
  "fork",
  "knife",
  "spoon",
  "bowl",
  "banana",
  "apple",
  "sandwich",
  "orange",
  "broccoli",
  "carrot",
  "hot dog",
  "pizza",
  "donut",
  "cake",
  "chair",
  "couch",
  "potted plant",
  "bed",
  "dining table",
  "toilet",
  "tv",
  "laptop",
  "mouse",
  "remote",
  "keyboard",
  "cell phone",
  "microwave",
  "oven",
  "toaster",
  "sink",
  "refrigerator",
  "book",
  "clock",
  "vase",
  "scissors",
  "teddy bear",
  "hair drier",
  "toothbrush"
]


