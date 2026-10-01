import { motion } from "framer-motion";
import { Navbar } from "@/components/landing/Navbar";
import { Hero } from "@/components/landing/Hero";
import { About } from "@/components/landing/About";
import { Ecc } from "@/components/landing/Ecc";
import { Features } from "@/components/landing/Features";
import { Comparison } from "@/components/landing/Comparison";
import { Solutions } from "@/components/landing/Solutions";
import { LiveConsole } from "@/components/landing/LiveConsole";
import { Vision } from "@/components/landing/Vision";
import { Roadmap } from "@/components/landing/Roadmap";
import { Pricing } from "@/components/landing/Pricing";
import { Faq } from "@/components/landing/Faq";
import { Contact } from "@/components/landing/Contact";
import { Footer } from "@/components/landing/Footer";

export default function Landing() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="min-h-screen bg-background text-foreground antialiased"
    >
      <Navbar />
      <main>
        <Hero />
        <About />
        <Ecc />
        <Features />
        <Comparison />
        <Solutions />
        <LiveConsole />
        <Vision />
        <Roadmap />
        <Pricing />
        <Faq />
        <Contact />
      </main>
      <Footer />
    </motion.div>
  );
}
