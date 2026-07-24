class PromptBuilder:

    def build(self, task, project_files):

        return f"""
You are an autonomous senior Python developer.

Project:
PurpleGuardAI

Task:
{task}

Files:
{project_files}

You must respond ONLY with valid JSON.

Format:

{{
  "files": [
    {{
      "path": "file/path.py",
      "content": "complete file content"
    }}
  ]
}}

Rules:
- Do not use markdown
- Do not explain
- Return only JSON
- Preserve existing functionality
"""
