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
cp config.example.yml config.yml  # 然后进行配置
cp .env.example .env              # 然后填写密钥
./aliyun-cdn-guard --check-config
./aliyun-cdn-guard
```

主要配置见 [`config.example.yml`](config.example.yml)，生产环境建议使用 ECS RAM 角色，需授权 log 和 CDN 服务的权限。

## Docker

```bash
docker run -d \
  --name aliyun-cdn-guard \
  --restart unless-stopped \
  -e ALIBABA_CLOUD_ACCESS_KEY_ID=your_access_key_id \
  -e ALIBABA_CLOUD_ACCESS_KEY_SECRET=your_access_key_secret \
  -v "$PWD/config.yml:/app/config.yml:ro" \
  -v "$PWD/data:/app/data" \
  chriskimzht/aliyun-cdn-guard:1
```

## 性能测试

使用以下指令进行性能测试，测试覆盖单 IP、多 IP 和每条请求不同 IP 三种场景，使用临时数据库，不修改生产数据、不调用阿里云 API。

```bash
./aliyun-cdn-guard --benchmark
./aliyun-cdn-guard --benchmark --config config.yml --benchmark-dir ./data --benchmark-duration 60s # 使用指定配置，在目标磁盘上测试
```

参考结果：阿里云 `ecs.t6-c1m2.large` (2 vCPU 4 GiB)

| 场景 | 日志处理 QPS | 平均批次耗时 | 最大批次耗时 |
| --- | ---: | ---: | ---: |
| 单 IP 持续攻击（hot） | 25,179 | 10.17 ms | 41.53 ms |
| 1024 个 IP 轮询（distributed） | 2,088 | 122.63 ms | 323.63 ms |
| 每条请求不同 IP（unique） | 23,260 | 11.01 ms | 46.04 ms |
