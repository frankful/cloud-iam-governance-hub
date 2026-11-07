import { type ReactNode, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import antdEnUS from "antd/locale/en_US";
import antdZhCN from "antd/locale/zh_CN";
import { ConfigProvider } from "antd";

/**
 * 让 antd 组件自带的文案（分页、日期选择器、空状态等）跟随界面语言。
 * i18next 的语言变化不会自动通知 antd 的 ConfigProvider，这里订阅一次。
 */
export function AntdLocaleProvider({ children }: { children: ReactNode }) {
  const { i18n } = useTranslation();
  const [locale, setLocale] = useState(i18n.resolvedLanguage === "en-US" ? antdEnUS : antdZhCN);

  useEffect(() => {
    const apply = (language: string) => {
      setLocale(language === "en-US" ? antdEnUS : antdZhCN);
    };
    apply(i18n.resolvedLanguage ?? i18n.language);
    i18n.on("languageChanged", apply);
    return () => {
      i18n.off("languageChanged", apply);
    };
  }, [i18n]);

  return <ConfigProvider locale={locale}>{children}</ConfigProvider>;
}
