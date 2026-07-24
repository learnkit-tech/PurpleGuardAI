class PromptBuilder:

    def build(self, task, project_files):

        prompt = f"""
You are an autonomous senior software engineer.

Project: PurpleGuardAI

Your job:
- Understand the requested feature
- Inspect existing code
- Decide which files need changes
- Write production-quality Python code
- Add tests
- Keep existing functionality working

Current task:
{task}

Project files:
{project_files}

Return:
1. Files to modify
2. Code changes required
3. Tests to add
4. Possible risks
"""

        return prompt
