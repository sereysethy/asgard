# type checking
from typing import Tuple

import requests

# our modules
from smartproxy.learning.environment.robertabase import RobertaBaseEnv
from smartproxy.monitor.monitorstats import MonitorStats as Monitor

class RobertaEnvWebV10(RobertaBaseEnv):
    """It reprensents the environment of Asgard2.0 but it calls
    the command risk assessment module via an external API to assess
    the risk level of a command.
    """
    def __init__(self, embedding_size: int, action_size: int, config: dict)->None:
        # load risk assessment
        self.api_url = config["api"]
        self.session = None

        # we have access to the target system stats, the target system is
        # defined in the configuration file.
        self.monitor = Monitor()

        super().__init__(action_size=action_size,
                         embedding_size=embedding_size,
                         config=config,
                         name="RobertaEnvWeb1.0")

    def getRiskAssessment(self, cmd: str)->Tuple[list[float], float, list[float]]:
        """
        Wrapper function over a classifier

        Args:
            cmd: raw command

        Returns:
            list: The list of the following values:
                - risk_level (list[float]): risk level associated to the passed command
                - prob (float): probability assessing that command
                - embedding (list[float]): tensor of the command embeddding
        """

        if not self.session:
            self.session = requests.Session()

        r = self.session.post(self.api_url, json={"raw_cmd": cmd})
        result = r.json()

        riskLevel = result["risk_level"]
        prob = result["probability"]
        embedding = result["embedding"]

        return riskLevel, prob, embedding
