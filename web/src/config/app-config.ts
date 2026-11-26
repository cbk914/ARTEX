import packageJson from "../../package.json";

import { t } from "@/i18n";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "ARTEX-Galactus",
  version: packageJson.version,
  copyright: `© ${currentYear}, ARTEX-Galactus.`,
  meta: {
    title: t("ARTEX-Galactus — Autonomous Penetration Testing Console"),
    description: t("Console for the LLM-driven autonomous penetration testing system"),
  },
};
