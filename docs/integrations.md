# Подключение интеграций

Встроенный демонстрационный сценарий запускается без доступа к сервисам. Для реальной отправки установите зависимости `python -m pip install -r requirements-integrations.txt`, задайте переменные нужных адаптеров и добавьте `--deliver` к команде `monitor`. Указывайте только значения для тех сервисов, которые подключаете. Секреты передавайте через окружение процесса или менеджер секретов.

| Адаптер | Переменные и настройка |
| --- | --- |
| Telegram | `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID`. Добавьте бота в выбранный чат и разрешите отправку. Вызов [Bot API sendMessage](https://core.telegram.org/bots/api#sendmessage). |
| Slack | `SLACK_WEBHOOK_URL`. Включите [Incoming Webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/) для выбранного канала. |
| AWS | `MONITOR_AWS_REGION`. Используйте профиль или IAM role, доступные через цепочку boto3. Требуется `cloudwatch:PutMetricData` для пространства имён `TechnoProfi/NetworkMonitor`. [CloudWatch API](https://docs.aws.amazon.com/boto3/latest/reference/services/cloudwatch/client/put_metric_data.html). |
| Azure | `AZURE_LOG_ENDPOINT`, `AZURE_DCR_ID` (immutable ID) и `AZURE_STREAM` (например, `Custom-NetworkMonitoring_CL`). Создайте Log Analytics custom table и DCR. Поля входного потока — `TimeGenerated` (datetime), `PacketsAnalyzed`, `DDoSIncidents`, `PeakDDoSPPS` (long). Назначьте удостоверению `Monitoring Metrics Publisher` на DCR. SDK использует `DefaultAzureCredential`. [Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview). |
| MISP | `MISP_URL` (корневой URL HTTPS) и `MISP_API_KEY` с доступом на чтение. Поиск точных `ip-src` / `ip-dst` у индикаторов с `to_ids=true`. [MISP Automation API](https://www.misp-project.org/openapi/). |
| OTX | `OTX_API_KEY`. Запрашивается число публичных pulses, связанных с IPv4/IPv6. [OTX SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK). |

Telegram и Slack получают сводку подозрений на DDoS за прогон. AWS и Azure получают агрегированные числа без IP-адресов. Для MISP и OTX запрашиваются до 10 публичных IP из наиболее активных источников обнаруженных инцидентов. Результаты поиска добавляются в JSON и журнал для расследования. Сбой одного адаптера фиксируется отдельно, остальные продолжают работу. Код выхода 2 означает частичную доставку; повторный запуск может отправить сводку повторно.

## Биометрический провайдер

Адаптер принимает подписанное утверждение после проверки лица, отпечатка, радужной оболочки или голоса в системе идентификации. Настройте HTTPS issuer `BIOMETRIC_ISSUER`, выделенную аудиторию `BIOMETRIC_AUDIENCE` и доверенный `BIOMETRIC_JWKS_URL`. Провайдер выдаёт JWT RS256 с `iss`, `aud`, `sub`, `iat`, `exp`, `auth_time`, `jti` и массивом `amr`, содержащим `face`, `fpt`, `iris` или `vbm`. Срок действия — не более 300 секунд с момента биометрической проверки. [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176.html).

Передайте JWT из брокера через stdin в `python -m traffic_monitor verify-biometrics`. Команда возвращает 0 при проверке, 1 при отказе и записывает результат в аудит. Хеш пары issuer и jti используется для отклонения повторного использования утверждения в той же базе. Подбор ключа выполняется по JWKS; подпись, issuer, audience, время и метод проверяются локально. Провайдер хранит и сравнивает биометрию. Команда подтверждает утверждение для системы мониторинга, а выдачу пользовательской сессии и авторизацию выполняет вызывающая система.
