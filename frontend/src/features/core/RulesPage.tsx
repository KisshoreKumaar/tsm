import { Card, ErrorBanner, Loading, SeverityBadge } from "../../core/ui";
import { useApiQuery } from "../../core/useApiQuery";
import type { Technique } from "./types";

interface RuleInfo {
  id: string;
  name: string;
  version: number;
  severity: string;
  confidence: number;
  stage: string;
  description: string;
  techniques: Technique[];
  builtin: boolean;
}

export function RulesPage() {
  const { data, error, loading } = useApiQuery<{ rules: RuleInfo[] }>("/rules");
  return (
    <section>
      <h1>Detection rules</h1>
      <ErrorBanner error={error} />
      {loading && !data && <Loading />}
      {data && (
        <Card>
          <table className="table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Severity</th>
                <th>Stage</th>
                <th>Logic</th>
                <th>Candidate techniques</th>
              </tr>
            </thead>
            <tbody>
              {data.rules.map((rule) => (
                <tr key={rule.id}>
                  <td className="mono">
                    {rule.id} v{rule.version}
                    <div className="small">{rule.name}</div>
                    <div className="muted small">{rule.builtin ? "built-in" : "custom"}</div>
                  </td>
                  <td>
                    <SeverityBadge severity={rule.severity} />
                    <div className="muted small">confidence {rule.confidence}</div>
                  </td>
                  <td>{rule.stage}</td>
                  <td className="small">{rule.description}</td>
                  <td className="small">
                    {rule.techniques.length === 0
                      ? "None (never invented)"
                      : rule.techniques.map((t) => (
                          <a key={t.id} href={t.url} target="_blank" rel="noreferrer noopener" className="technique">
                            {t.id} {t.name}
                          </a>
                        ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </section>
  );
}
