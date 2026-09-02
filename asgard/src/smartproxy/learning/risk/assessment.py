import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

from transformers import AutoTokenizer

from .model import MLP

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
cpu = torch.device("cpu")

class RiskAssessment():
    """
    This class will load a trained risk assessment model which will assess
    a risk associated to a command.
    """

    def __init__(self, config:dict)->None:
        # initialize the class attributes from the model configuration
        self.max_len: int = config["token_max_length"]
        self.bert_model: str = config["pre_trained_model_checkpoint"]
        self.model_path = config["risk_model_path"]
        self.input_size = config["input_size"]
        self.hidden_size = config["hidden_size"]
        self.output_size = config["output_size"]

        # create a model
        self.model = self.make_model(self.input_size, self.hidden_size, \
                                    self.output_size, self.bert_model)

        # initialized from a trained model
        self.load_trained_model(self.model_path)

        self.tokenizer = self.get_tokenizer(self.bert_model)

    def make_model(self, input_size: int, hidden_size:int, output_size:int,\
                    bert_model: str):
        """
        Return a new model (instance) of a MLP class.

        It creates an instance of :class:`smartproxy.learning.risk.model.MLP`,
        and returns it. This instance is used to load an already
        trained model.
        """
        model = MLP(input_size, hidden_size, output_size, bert_model)

        return model

    def get_tokenizer(self, model_ckpt):
        """
        Instantiate one of the tokenizer classes of the library from a pretrained model vocabulary.

        Args:
            model_ckpt: path to the saved pre-trained model.
        """
        tokenizer = AutoTokenizer.from_pretrained(model_ckpt)

        return tokenizer

    def tokenize(self, text):
        """
        Return tokens for the input `text`.

        Args:
            text: The text to tokenize using the ``self.tokenizer``.

        Returns:
            dict: A dictionary containing:
                - ids: Input token IDs (torch.long tensor)
                - mask: Attention mask indicating real tokens vs padding (torch.long tensor)
                - token_type_ids: Segment IDs for distinguishing sequences (torch.long tenso
        """
        # Tokenize the input text with the following configurations:
        # - add_special_tokens: Add [CLS] and [SEP] tokens
        # - truncation: Truncate sequences longer than max_length
        # - max_length: Maximum sequence length
        # - padding: Pad shorter sequences to max_length
        # - return_token_type_ids: Include segment token indices
        inputs = self.tokenizer(text,
                    add_special_tokens=True,
                    truncation=True,
                    max_length=self.max_len,
                    padding='max_length',
                    return_token_type_ids=True)

        # Extract token IDs for the input sequence
        ids = inputs['input_ids']

        # Extract attention mask (1 for real tokens, 0 for padding)
        mask = inputs['attention_mask']

        # Extract token type IDs (for sequence pair tasks)
        token_type_ids = inputs["token_type_ids"]

        # Convert to PyTorch tensors and return as dictionary
        return {
            'ids': torch.tensor(ids, dtype=torch.long),
            'mask': torch.tensor(mask, dtype=torch.long),
            'token_type_ids': torch.tensor(token_type_ids, dtype=torch.long)
        }

    def load_trained_model(self, model_path)->None:
        """
        Load a model from a already trained model.

        Args:
            model_path (str): path to the trained model.
        """
        if torch.cuda.is_available():
            checkpoint = torch.load(model_path)
        else:
            checkpoint = torch.load(model_path, map_location=torch.device('cpu'))
        self.model.load_state_dict(checkpoint['model_state_dict'])

    def get_risk(self, cmd: list)->dict[list[float], float, list[float]]:
        """
        Return a dictonary of risk level, probability and embeddingins
        associated to a command.

        Args:
            cmd: A list of commands (str). Although it takes a list of commands,
            but this method only returns a single risk level for a single command.
        Returns:
            dict: A dictionary of:
                - risk_level (int): a list of risk level ranging from `0` to `4`.
                - probability (float): Risk assessment probability.
                - embedding: embeddings of the token corresponding the input command.
        """
        # Initialize output variables
        risk_level = 0.
        prob = 0.
        pooler = None

        # Set model to evaluation mode (disable dropout, etc.)
        self.model.eval()

        # Disable gradient computation for inference
        with torch.no_grad():
            # Tokenize the input command
            data = self.tokenize(cmd)

            # Move tensors to the appropriate device (CPU/GPU)
            ids = data['ids'].to(device, dtype = torch.long)
            mask = data['mask'].to(device, dtype = torch.long)
            token_type_ids = data['token_type_ids'].to(device, dtype = torch.long)

            # Forward pass through the model
            outputs, output_1 = self.model(ids, mask, token_type_ids)

            # Compute softmax probabilities for each risk class
            predicted_probs = F.softmax(outputs, dim=1)

            # Get the highest probability and its corresponding class
            top_probs, top_classes = predicted_probs.topk(1, dim=1)

            # Extract [CLS] token embedding from the transformer output
            hidden_state = output_1[0]
            pooler = hidden_state[:, 0].numpy()

            # Get the predicted risk class (argmax of logits)
            risk_level = outputs.argmax(1).cpu()

            # Convert predicted class to one-hot encoded vector
            risk_level = F.one_hot(risk_level,
                                num_classes=self.output_size).numpy().tolist()

            # Extract the probability score as a float
            prob = top_probs.squeeze().cpu().numpy().tolist()

        # Return risk assessment results as a dictionary
        return {
            "risk_level": risk_level[0],
            "probability": prob,
            "embedding": pooler[0]
        }

