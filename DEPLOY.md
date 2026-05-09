# Private Hugging Face Space Deployment

Use this folder as the Space repository contents.

## Recommended Settings

- Visibility: Private
- SDK: Gradio
- App file: `app.py`

## Files To Upload

Upload everything inside this `hf-space/` folder, including:

- `app.py`
- `requirements.txt`
- `README.md`
- `.gitattributes`
- `scanner/`
- `codebert_vuln_type_model/`

Do not upload the original project documents, local SQLite database, checkpoint folders, or zip files.

## Git Upload Flow

```powershell
cd "C:\Users\BaeGeunha\Desktop\grape 프로젝트\hf-space"
git init
git lfs install
git add .
git commit -m "Deploy private AI vulnerability scanner"
git branch -M main
git remote add origin https://huggingface.co/spaces/<your-username>/<your-private-space-name>
git push -u origin main
```

If the Space already has files, clone it first and copy this folder's contents into the cloned Space repository.
