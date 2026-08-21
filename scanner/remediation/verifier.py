class PatchVerifier:

    def verify(self, original_finding, patch_result):
        if patch_result["after"] is None:
            return {
                "status": "FAILED",
                "message": "No fix generated"
            }

        return {
            "status": "PASSED",
            "message": "Patch generated successfully"
        }
