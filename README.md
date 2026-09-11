This repository contains the code for our paper accepted at ACM CCS. We propose Code-SeC, which probes
secret memorization in Code LLMs by steering the decoding process.

## Method
<img src="Code-SeC/plots/CCS-method-v2.png" alt="Overview of Code-SeC" width="1000">

## Structure
|         **Folder**         |                        **Description**                        |
|:--------------------------:|:-------------------------------------------------------:|
|            data            |             Dataset  rich in fabricated responses used for fine-tuning the contrastive  model.                |
|       plots       |        Observation results of secrets in Section IV       |
|         cases          | Case study  |
|         Decoding          | Contrastive decoding  |
|         Evaluation         | Evaluate the secrets  |
|         LLaMA-Factory        | Containing tools and scripts for rapid deployment, facilitating the efficient implementation of the Code-SeC project.  |


Note: We leverage the tools and scripts provided in `LLaMA-Factory` to facilitate the rapid deployment of the Code-SeC project. These resources greatly simplify the entire process of Code-SeC. Refer to `LLaMA-Factory` for more details: https://github.com/hiyouga/LLaMA-Factory.

## Usage
1. Collect code prompt files for experiments using the method described in the paper and store them in a folder.
2. For the dataset in `Data`, you can directly use these datasets. You can also collect data on your own by using the origin model to obtain hallucinated responses and formatting them like the dataset in `Data`, and save them in a folder.

3. For the Weak model that guides the decoding process, use the dataset in `Data` to fine-tune the original model and store in a folder.

4. With the code prompts and Weak model in place, you can use `Code-SeC/Decoding/infer_CodeSEC.py` in `Decoding`. Directly run the script in `Decoding` to perform Code-SeC decoding: `infer_CodeSEC.sh`. Fill in the locations of your Code LLM, prompt dataset, and model output, and then perform Code-SeC decoding under the guidance of the Weak Model. You can also change the hyperparameters in `Decoding/infer_CodeSEC.py` to adjust the decoding process.
5. Use the scripts under `Code-SeC/Evaluation/result_eval/` to extract and evaluate plausible secrets from model outputs. For JSONL outputs, set `OUTPUT_FILE` and run `eval_jsonl.sh`; for JSON outputs, set `OUTPUT_FILE` and run `eval_json.sh`. The pipeline first restores prefix context, filters plausible secrets, and then writes validation summaries with `RS_main.py`.

Due to user privacy concerns, the released artifact is intended for plausible-secret evaluation and does not include our private prompt corpus.

## License
Code-SeC is released under the Apache License 2.0. The included `Code-SeC/LLaMA-Factory` component is derived from the LLaMA-Factory project and retains its Apache License 2.0 license terms.
## Ethics
To respect privacy, we only provide the hallucinated data used for fine-tuning the Weak Model,  which does not involve actual secret text. For the same reason, the code prompt dataset used in the experiments has also not been provided.
## Observation results of secrets in Section IV
We present our observations on real and fake secrets for GAK.
**Accuracy of cumulative entropy in identifying invalid secret tokens.**
<img src="Code-SeC/plots/uncertainty-rev.png" alt="Uncertainty-based secret detection results" width="1000">










### Case Study
We illustrate secret generation examples and their token uncertainty.

<img src="Code-SeC/cases/CCS-case-main.png" alt="Secret generation case study" width="1000">

