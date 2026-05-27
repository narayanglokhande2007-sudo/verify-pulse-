import json
import os
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer, DataCollatorForLanguageModeling
from peft import LoraConfig, get_peft_model, TaskType
from datasets import Dataset
from huggingface_hub import HfApi, upload_folder

HF_TOKEN = os.environ['HF_TOKEN']
MASTER_FILE = 'pipeline/daily-data/all_scams_master.jsonl'
REPO_ID = 'VerifyPulse384556/verifypulse-scam-detector'   # your Hugging Face model repo

print("📊 Loading all scam URLs from master file...")
urls = []
with open(MASTER_FILE, 'r', encoding='utf-8') as f:
    for line in f:
        try:
            data = json.loads(line)
            urls.append(data['url'])
        except:
            pass

print(f"Total URLs in master dataset: {len(urls)}")

# Training prompt format (system + user + assistant)
system_prompt = """You are an Indian scam detection expert. Analyze the URL and return a JSON object with:
- verdict: DANGEROUS
- scamType: Phishing Attack
- confidence: 100
- analysis: This URL is known phishing/scam from threat feed.
- findings: ["Verified scam URL"]
- whatToDo: ["Do not visit this link", "Report if you received it"]"""

texts = []
for url in urls:
    texts.append(f"System: {system_prompt}\nUser: Check this URL: {url}\nAssistant: {{\"verdict\": \"DANGEROUS\", \"scamType\": \"Phishing Attack\", \"confidence\": 100, \"analysis\": \"This URL is a known phishing/scam link.\", \"findings\": [\"Verified scam URL\"], \"whatToDo\": [\"Do not visit\", \"Report to authorities\"]}}")

dataset = Dataset.from_dict({"text": texts})

# Load base model (DistilGPT2 – change if needed)
model_name = "distilgpt2"
tokenizer = AutoTokenizer.from_pretrained(model_name)
tokenizer.pad_token = tokenizer.eos_token
model = AutoModelForCausalLM.from_pretrained(model_name)

# LoRA config
lora_config = LoraConfig(
    r=4,
    lora_alpha=8,
    target_modules=["c_attn"],
    lora_dropout=0.05,
    bias="none",
    task_type=TaskType.CAUSAL_LM
)
model = get_peft_model(model, lora_config)

def tokenize(examples):
    return tokenizer(examples["text"], truncation=True, max_length=256, padding="max_length")

tokenized_dataset = dataset.map(tokenize, batched=True)

# Training arguments (CPU only, full dataset)
training_args = TrainingArguments(
    output_dir="./scam-model-full",
    num_train_epochs=1,
    per_device_train_batch_size=1,
    gradient_accumulation_steps=4,
    save_steps=10000,
    logging_steps=500,
    learning_rate=5e-5,
    report_to="none",
    fp16=False,
    no_cuda=True,
    save_total_limit=2,
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset,
    data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)
)

print("🚀 Training started on full dataset...")
trainer.train()
print("✅ Training complete!")

# Merge LoRA and save full model
merged_model = model.merge_and_unload()
merged_model.save_pretrained("./merged-scam-model")
tokenizer.save_pretrained("./merged-scam-model")

# Upload to Hugging Face (replace old model)
api = HfApi()
api.delete_folder(repo_id=REPO_ID, path_in_repo="", token=HF_TOKEN)   # clear old files
upload_folder(
    folder_path="./merged-scam-model",
    repo_id=REPO_ID,
    token=HF_TOKEN,
    repo_type="model",
    commit_message="🤖 Daily retrain on full collected dataset"
)
print("🎉 Model uploaded to Hugging Face successfully!")
