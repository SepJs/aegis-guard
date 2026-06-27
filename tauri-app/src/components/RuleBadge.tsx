interface Props { rule: string; }
export default function RuleBadge({ rule }: Props) {
  const cls = rule.startsWith("PAR")  ? "rule-badge--par"
            : rule.startsWith("PATH") ? "rule-badge--path"
            : rule.startsWith("ARG")  ? "rule-badge--arg"
            : rule.startsWith("ENV")  ? "rule-badge--env"
            : "rule-badge--unk";
  const title = rule.startsWith("PAR")  ? "Suspicious parentage"
              : rule.startsWith("PATH") ? "Anomalous exec path"
              : rule.startsWith("ARG")  ? "Cmdline obfuscation"
              : rule.startsWith("ENV")  ? "Env manipulation"
              : rule;
  return <span className={`rule-badge ${cls}`} title={title}>{rule}</span>;
}
