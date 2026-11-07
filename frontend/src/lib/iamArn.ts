/**
 * 从 IAM ARN 反解资源的 path。
 *
 * 纳管（import）已存在资源时，声明里的 `path` 必须与 AWS 上的真实值一致：
 *  - 托管策略的 import ID 就是 ARN（`arn:aws:iam::<账号>:policy<path><name>`），
 *    path 填错会构造出不存在的 ARN，apply 直接失败；
 *  - 用户/角色/组的 path 是 ForceNew 属性，声明与真实值不一致时 Terraform
 *    会计划「替换」资源，ARN 随之变化，附加的策略与实例配置全部断裂。
 *
 * 资产清单里已经有 ARN，没必要再让用户手抄 path。
 */
export function iamPathFromARN(arn: string, resourceType: string): string {
  const marker = `:${resourceType}/`;
  const index = arn.indexOf(marker);
  if (index < 0) return "/";
  // path 与资源名之间以斜杠分隔；没有斜杠说明资源就在根路径下。
  const remainder = arn.slice(index + marker.length);
  const lastSlash = remainder.lastIndexOf("/");
  if (lastSlash < 0) return "/";
  return remainder.slice(0, lastSlash + 1);
}
