import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Reveal } from "./Reveal";
import { SectionHeader } from "./SectionHeader";
import { FAQS } from "./data";

export function Faq() {
  return (
    <section id="faq" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-3xl px-4 sm:px-6 lg:px-8">
        <SectionHeader
          eyebrow="FAQ"
          title="Questions, answered"
          description="Everything you need to know about AI security, privacy, integrations, pricing, compliance, and enterprise deployment."
        />

        <Reveal delay={0.1} className="mt-12">
          <Accordion
            type="single"
            collapsible
            className="overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.02] px-5 sm:px-6"
          >
            {FAQS.map((faq, i) => (
              <AccordionItem
                key={faq.question}
                value={`item-${i}`}
                className="border-white/[0.06]"
              >
                <AccordionTrigger className="py-5 text-left text-sm font-medium text-foreground hover:no-underline data-[state=open]:text-violet-200 [&>svg]:text-violet-300">
                  {faq.question}
                </AccordionTrigger>
                <AccordionContent className="text-sm leading-relaxed text-muted-foreground">
                  {faq.answer}
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </Reveal>

        <Reveal delay={0.16}>
          <p className="mt-8 text-center text-sm text-muted-foreground">
            Still have questions?{" "}
            <a
              href="#contact"
              className="font-medium text-violet-300 underline-offset-4 transition-colors hover:text-violet-200 hover:underline"
            >
              Talk to the team
            </a>
          </p>
        </Reveal>
      </div>
    </section>
  );
}
