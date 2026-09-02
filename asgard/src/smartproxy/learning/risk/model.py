import torch
import torch.nn as nn

from transformers import AutoModel

class MLP(nn.Module):
    """
    Multi-layer Perceptron for the risk assessment model.

    It uses a pre-trained language model RoBERTa from HuggingFace.
    """
    def __init__(self, input_size, hidden_size, output_size, model_ckpt):
        """
        Initialize the MLP model with a pre-trained transformer and classification layers.

        Args:
            input_size: Dimension of the transformer's output embeddings (e.g., 768 for RoBERTa-base)
            hidden_size: Dimension of the hidden layer in the classification head
            output_size: Number of output classes for risk assessment
            model_ckpt: HuggingFace model checkpoint identifier (e.g., 'roberta-base')
        """
        super(MLP, self).__init__()
        # Load pre-trained transformer model (RoBERTa)
        self.l1 = AutoModel.from_pretrained(model_ckpt)
        # Classification head: maps transformer output to hidden dimension
        self.pre_classifier = torch.nn.Linear(input_size, hidden_size)
        # Dropout for regularization
        self.dropout = torch.nn.Dropout(0.3)
        # Final classifier: maps hidden state to output classes
        self.classifier = torch.nn.Linear(hidden_size, output_size)

    def forward(self, input_ids, attention_mask, token_type_ids):
        """
        Forward pass through the model.

        Args:
            input_ids: Token indices from the tokenizer
            attention_mask: Mask to avoid attention on padding tokens
            token_type_ids: Segment token indices (for distinguishing sequences)

        Returns:
            output: Final classification logits (batch_size, output_size)
            output_1: Full transformer output (for potential auxiliary tasks)
        """
        # Pass inputs through the pre-trained transformer
        output_1 = self.l1(input_ids=input_ids, attention_mask=attention_mask, token_type_ids=token_type_ids)
        # Extract hidden states for all tokens
        hidden_state = output_1[0]
        # Use [CLS] token representation (first token) for classification
        pooler = hidden_state[:, 0]
        # Pass through pre-classifier layer
        pooler = self.pre_classifier(pooler)
        # Apply ReLU activation
        pooler = torch.nn.ReLU()(pooler)
        # Apply dropout for regularization
        pooler = self.dropout(pooler)
        # Generate final classification output
        output = self.classifier(pooler)
        return output, output_1
