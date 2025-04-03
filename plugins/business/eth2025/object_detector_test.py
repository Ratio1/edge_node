from ratio1 import Instance, Payload, Pipeline, Session


def instance_on_data(pipeline: Pipeline, data: Payload):
  # the images can be extracted from the Payload object
  # PIL needs to be installed for this to work
  # images = data.get_images_as_PIL()
  # if images is not None:
  #   if len(images) > 0 and images[0] is not None:
  #     images[0].save('frame.jpg')

  pipeline.P('Received1 DATAA: ', data)
  pipeline.P('Received3 DATA: ', data.data)
  pipeline.P(data.data.get('OBJECTS', []))



if __name__ == '__main__':

  session: Session = Session()

  # this code assumes the node have "allowed" the SDK to deploy the pipeline
  nodes = [
    '0xai_A7NhKLfFaJd9pOE_YsyePcMmFfxmMBpvMA4mhuK7Si1w',
  ]

  for node in nodes:
    print('node::: ')
    print(node)
    session.wait_for_node(node)  # we wait for the node to be ready
    pipeline: Pipeline = session.create_pipeline(
      node=node,
      name='object_detector_pipeline',
      data_source="VideoFile",
      config={
        'URL': "https://www.dropbox.com/scl/fi/8z2wpeelhav3k2dv8bb5p/Cars_3.mp4?rlkey=imv415rr3j1tx3zstpurlxkqb&dl=1"
      }
    )

    instance: Instance = pipeline.create_plugin_instance(
      signature='OBJECT_DETECTOR',
      instance_id='inst01',
      on_data=instance_on_data,
      config={
        'ADD_ORIGINAL_IMAGE': False,
        'OBJECT_TYPE': ['person']
      }
    )

    pipeline.deploy()

  session.wait(
    seconds=99999999,  # we wait the session for 60 seconds
    close_pipelines=True,  # we close the pipelines after the session
    close_session=True,  # we close the session after the session
    # wait=True
  )
  session.P("Main thread exiting...")
