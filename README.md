# aliyun-cdn-guard

从阿里云 SLS 实时消费 CDN 访问日志，识别高频恶意请求来源并封禁，并自动维护对应域名的 CDN IP 黑名单。

## 功能

- 按 IP，或 `IP + UA/URI` 统计滑动窗口内的请求数
- 支持域名、IP/CIDR、UA 和 URI 白名单
- 支持递增封禁时长与永久黑名单
- 封禁到期后仅移除本程序添加的条目
- 使用 SQLite 保存事件、处罚记录和条目归属
- 将每次新产生的封禁追加写入 `data/blocks.jsonl`，便于审计和离线分析
- 支持 `dry_run`，便于上线前观察规则效果

## 快速开始

```bash
go build -o aliyun-cdn-guard ./cmd/aliyun-cdn-guard
cp config.example.yml config.yml  # 然后进行配置
cp .env.example .env              # 然后填写密钥
./aliyun-cdn-guard --check-config
./aliyun-cdn-guard
```

主要配置见 [`config.example.yml`](config.example.yml)，生产环境建议使用 ECS RAM 角色，需授权 log 和 CDN 服务的权限。

## Docker

```bash
docker build -t aliyun-cdn-guard .
docker run -d \
  --name aliyun-cdn-guard \
  --restart unless-stopped \
  -e ALIBABA_CLOUD_ACCESS_KEY_ID=your_access_key_id \
  -e ALIBABA_CLOUD_ACCESS_KEY_SECRET=your_access_key_secret \
  -v "$PWD/config.yml:/app/config.yml:ro" \
  -v "$PWD/data:/app/data" \
  aliyun-cdn-guard
```

## 性能参考

当前实现为每个有效请求单独提交一次 SQLite 事务，本机微基准约为 450 QPS，热点流量持续累积时会进一步下降。

| 持续输入速率 | 预期状态 |
| --- | --- |
| 低于 100 QPS | 通常较稳妥 |
| 100–250 QPS | 建议的生产运行区间 |
| 250–400 QPS | 容易受到热点流量和磁盘性能影响 |
| 持续超过 400 QPS | 可能产生 SLS 消费积压 |
