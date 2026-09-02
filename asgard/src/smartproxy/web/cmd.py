from typing import Union, List
from pydantic import BaseModel

class Payload(BaseModel):
    raw_cmd: str
    basename: str
    exec_cmd: str
    cmd_exec_state: int
    exploration: bool
    mask: Union[List, None]
    avg_cpu: float
    avg_mem: float
    
