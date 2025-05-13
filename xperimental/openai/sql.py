"""
```bash
pip install openai
```

"""
import json
import os
import dotenv

from openai import OpenAI


if __name__ == "__main__":
  dotenv.load_dotenv()
  
    
  INSTRUCTIONS = """You are a SQL expert. 
You will be given a data structure presentation and your task is to create the DDL (Data Definition Language) for the database. You will be given a data structure presentation and your task is to create the DDL (Data Definition Language) for the database. You will be given a data structure presentation and your task is to create the DDL (Data Definition Language) for the database. You will be given a data structure presentation and your task is to create the DDL (Data Definition Language) for the underlying database. You will be given a data structure presentation and your task is to create the DDL (Data Definition Language) for the underlying database. You will be given a data structure presentation and your task is to create the DDL (Data Definition Language) for the underlying database. You will be given a data structure presentation and your task is to create the DDL (Data Definition Language) for the underlying database. You will be given a data structure presentation and your task is to create the DDL (Data Definition Language) for the underlying tables creation. 
Your responses will be strictly the SQL output with extensive SQL comments that will also include table normalization information.
"""

  query = """
  I need a basic invoice management system.
  """

  client = OpenAI(
    api_key=os.environ["EE_API_KEY"],
  )
  
  result = client.responses.create(
    model="gpt-4.1-mini",
    instructions=INSTRUCTIONS,
    input=query
  )
  
  print(result.output_text)
  
