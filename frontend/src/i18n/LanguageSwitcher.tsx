import { Select } from "antd";
import { useTranslation } from "react-i18next";
import { SUPPORTED_LANGUAGES, persistLanguage } from "../i18n";

// 语言切换：写入 localStorage 并立即切换 i18next 的当前语言。
export function LanguageSwitcher() {
  const { t, i18n } = useTranslation();

  return (
    <Select
      size="small"
      style={{ minWidth: 110 }}
      value={i18n.resolvedLanguage ?? i18n.language}
      aria-label={t("common.language")}
      title={t("common.language")}
      options={SUPPORTED_LANGUAGES.map((language) => ({
        value: language.value,
        label: language.label,
      }))}
      onChange={(value: string) => {
        persistLanguage(value);
        void i18n.changeLanguage(value);
      }}
    />
  );
}
