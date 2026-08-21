class PurpleGuardPipeline:

    def __init__(
        self,
        analyzer,
        scanner,
        attack_graph,
        reasoner,
        patch_generator,
        verifier
    ):
        self.analyzer = analyzer
        self.scanner = scanner
        self.attack_graph = attack_graph
        self.reasoner = reasoner
        self.patch_generator = patch_generator
        self.verifier = verifier


    def run(self, project_path):

        print("[1] Understanding project...")
        context = self.analyzer.analyze()


        print("[2] Scanning vulnerabilities...")
        findings = self.scanner.scan(project_path)


        print("[3] AI security reasoning...")
        analysis = []

        for finding in findings:
            result = self.reasoner.reason(
                finding,
                context
            )

            analysis.append(result)


        print("[4] Building attack graph...")
        attack_graph = self.attack_graph.build(
            findings
        )


        print("[5] Generating fixes...")
        patches = []

        for finding in findings:
            patches.append(
                self.patch_generator.generate_patch(
                    finding
                )
            )


        print("[6] Verifying...")
        verification = self.verifier.run_tests(
            project_path
        )


        return {
            "context": context,
            "findings": findings,
            "ai_analysis": analysis,
            "attack_graph": attack_graph,
            "patches": patches,
            "verification": verification
        }
