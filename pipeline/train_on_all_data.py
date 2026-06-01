import json
import os
import torch
import zipfile
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer, DataCollatorForLanguageModeling
from peft import LoraConfig, get_peft_model, TaskType
from datasets import Dataset
from huggingface_hub import HfApi, upload_folder

HF_TOKEN = os.environ.get('HF_TOKEN')
if not HF_TOKEN:
    print("⚠️ HF_TOKEN environment variable not set. Hugging Face uploads will be skipped.")

MASTER_FILE = 'pipeline/daily-data/all_scams_master.jsonl'
LATEST_FILE = 'pipeline/daily-data/latest_scams.json'
REPO_ID = 'VerifyPulse384556/verifypulse-scam-detector'

print("📊 Loading scam URLs...")
urls = []

# 1. Load active data from master file
if os.path.exists(MASTER_FILE):
    print(f"Loading from master file: {MASTER_FILE}")
    with open(MASTER_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                data = json.loads(line)
                urls.append(data['url'])
            except:
                pass

# 2. Load historical data from ZIP archives (Never Forget Memory)
ARCHIVE_DIR = 'pipeline/daily-data/archives'
if os.path.exists(ARCHIVE_DIR):
    for filename in os.listdir(ARCHIVE_DIR):
        if filename.endswith('.zip'):
            zip_path = os.path.join(ARCHIVE_DIR, filename)
            print(f"📦 Loading historical data from archive: {filename}")
            try:
                with zipfile.ZipFile(zip_path, 'r') as zipf:
                    for name in zipf.namelist():
                        if name.endswith('.jsonl'):
                            with zipf.open(name) as f:
                                for line in f:
                                    try:
                                        data = json.loads(line.decode('utf-8'))
                                        urls.append(data['url'])
                                    except:
                                        pass
            except Exception as e:
                print(f"❌ Error reading zip {filename}: {e}")
else:
    print(f"⚠️ {MASTER_FILE} not found. Checking fallback file: {LATEST_FILE}")
    if os.path.exists(LATEST_FILE):
        try:
            with open(LATEST_FILE, 'r', encoding='utf-8') as f:
                urls = json.load(f)
        except Exception as e:
            print(f"❌ Error loading fallback JSON file: {e}")
    else:
        print("❌ No threat data files found. Cannot proceed with training.")

print(f"Total URLs in dataset (Active + Archived): {len(urls)}")

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

model_name = "distilgpt2"
tokenizer = AutoTokenizer.from_pretrained(model_name)
tokenizer.pad_token = tokenizer.eos_token
model = AutoModelForCausalLM.from_pretrained(model_name)

lora_config = LoraConfig(r=4, lora_alpha=8, target_modules=["c_attn"], lora_dropout=0.05, bias="none", task_type=TaskType.CAUSAL_LM)
model = get_peft_model(model, lora_config)

def tokenize(examples):
    return tokenizer(examples["text"], truncation=True, max_length=256, padding="max_length")
tokenized_dataset = dataset.map(tokenize, batched=True)

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
    use_cpu=True,
    save_total_limit=2,
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset,
    data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)
)

print("🚀 Training started on full historical dataset...")
trainer.train()
print("✅ Training complete!")

merged_model = model.merge_and_unload()
merged_model.save_pretrained("./merged-scam-model")
tokenizer.save_pretrained("./merged-scam-model")

if HF_TOKEN and len(urls) > 0:
    print("🚀 Uploading to Hugging Face...")
    try:
        api = HfApi()
        try:
            api.delete_folder(repo_id=REPO_ID, path_in_repo="", token=HF_TOKEN)
        except Exception as e:
            print(f"Note: Could not delete folder (might not exist yet): {e}")
        
        upload_folder(
            folder_path="./merged-scam-model",
            repo_id=REPO_ID,
            token=HF_TOKEN,
            repo_type="model",
            commit_message="🤖 Weekly retrain on full historical dataset"
        )
        print("🎉 Model uploaded to Hugging Face successfully!")
    except Exception as e:
        print(f"❌ Upload failed: {e}")
else:
    if not HF_TOKEN:
        print("ℹ️ Model upload skipped because HF_TOKEN is not set.")
    else:
        print("ℹ️ Model upload skipped because dataset is empty.")
