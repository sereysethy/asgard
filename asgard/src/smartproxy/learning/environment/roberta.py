# type checking
from typing import Tuple

# our modules
from smartproxy.learning.environment.robertabase import RobertaBaseEnv
from smartproxy.monitor.monitorstats import MonitorStats as Monitor
from smartproxy.learning.risk.assessment import RiskAssessment

class RobertaEnvV10(RobertaBaseEnv):
    """It reprensents the environment of Asgard2.0 but it includes the
    command risk assessment module.
    """
    def __init__(self, embedding_size: int, action_size: int, config: dict)->None:
        # we have access to the target system stats, the target system is
        # defined in the configuration file.
        self.monitor = Monitor()

        # load risk assessment
        self.classifier = RiskAssessment(config)

        super().__init__(action_size=action_size,
                         embedding_size=embedding_size,
                         config=config,
                         name="RobertaEnv1.0")

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

        result = self.classifier.get_risk([cmd])
        riskLevel = result["risk_level"]
        prob = result["probability"]
        embedding = result["embedding"]

        return riskLevel, prob, embedding
