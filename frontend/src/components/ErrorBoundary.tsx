import { Component, type ErrorInfo, type ReactNode } from "react";
import { Alert, Button, Result } from "antd";
import i18n from "../i18n";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/** 全局错误边界：单页崩溃时保留导航可用 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("页面渲染失败:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      const t = i18n.t.bind(i18n);
      return (
        <div className="page">
          <Result
            status="error"
            title={t("error.boundaryTitle")}
            subTitle={this.state.error.message}
            extra={
              <Button type="primary" onClick={() => this.setState({ error: null })}>
                {t("error.reload")}
              </Button>
            }
          />
          <Alert type="warning" message={this.state.error.message} />
        </div>
      );
    }
    return this.props.children;
  }
}
