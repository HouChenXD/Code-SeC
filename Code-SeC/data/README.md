# Data

This directory contains the public datasets used by Code-SeC for fine-tuning the weak model and running the released examples.

## Files

- `dataset_info.json`: dataset registry consumed by LLaMA-Factory.
- `bad_dataset_acak_codellama.json`: fabricated responses for Alibaba Cloud access key examples.
- `bad_dataset_gak_codellama.json`: fabricated responses for Google API key examples.
- `bad_dataset_goci_codellama.json`: fabricated responses for Google OAuth client ID examples.
- `bad_dataset_siwu_codellama.json`: fabricated responses for Slack incoming webhook URL examples.
- `bad_dataset_stsk_codellama.json`: fabricated responses for Stripe test secret key examples.
- `bad_dataset_tcsi_codellama.json`: fabricated responses for Tencent Cloud secret ID examples.
- `alpaca_en_demo.json`, `alpaca_zh_demo.json`, `identity.json`, `wiki_demo.txt`: demo data inherited from the LLaMA-Factory data layout.

The `bad_dataset_*_codellama.json` files follow Alpaca-style JSON records with `instruction` and `output` fields. Their corresponding column mapping is declared in `dataset_info.json`.

## Usage

Place this directory as the LLaMA-Factory `dataset_dir`, then select one of the dataset names declared in `dataset_info.json`. For example:

```yaml
dataset_dir: Code-SeC/data
dataset: bad_dataset_gak_codellama
```

For custom data, create JSON records with the same `instruction` and `output` fields, add a dataset entry to `dataset_info.json`, and point `file_name` to the new file.

## Privacy Note

The released fine-tuning data contains fabricated or placeholder responses for studying plausible secret memorization. The private prompt corpus used in the paper is not included.
