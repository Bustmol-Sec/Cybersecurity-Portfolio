# Lab 01 — Instalación y configuración de Wazuh SIEM

## Objetivo
Montar un entorno de monitoreo real con Wazuh Server 
en Ubuntu y agente en Windows 11 en red local.

## Entorno
| Componente | Detalle |
|------------|---------|
| Servidor   | Ubuntu — Wazuh Server 4.7 |
| Agente     | Windows 11 |
| Red        | LAN local 192.168.XXX.0/24 |
| SIEM       | Wazuh Dashboard |

## Herramientas usadas
- Wazuh 4.7
- Ubuntu Server
- Windows 11
- PowerShell
- Terminal Linux

## Pasos realizados
1. Instalación de Wazuh Server en Ubuntu
2. Configuración de servicios (indexer, manager, dashboard)
3. Resolución de errores de arranque
4. Instalación de agente en Windows 11
5. Conexión agente → servidor verificada

## Troubleshooting resuelto
- Servicios wazuh-indexer y wazuh-manager caídos al inicio
- API timeout al cargar el dashboard
- Configuración de logs de Windows pendiente (próxima sesión)
## Servicios Wazuh-Indexer y Wazuh-Manager activos
<img width="1366" height="735" alt="image" src="https://github.com/user-attachments/assets/fec2e84a-a63e-4b5e-8261-794ca02dd301" />


## Resultado
✅ Agente Windows 11 conectado y visible en dashboard

## Dashboard Wazuh funcionando
<img width="1600" height="1200" alt="image" src="https://github.com/user-attachments/assets/24b24010-baed-430f-867c-098e69da2f0e" />
## Agente Windows 11 conectado
<img width="1359" height="656" alt="image" src="https://github.com/user-attachments/assets/c344b37f-7826-407f-836b-e8b458badf1f" />
<img width="1361" height="607" alt="image" src="https://github.com/user-attachments/assets/93de0e83-c60d-455c-8554-544f2004f694" />
<img width="1361" height="615" alt="image" src="https://github.com/user-attachments/assets/03728405-dbf7-4117-b110-ecf2db7a36f4" />



## Próximos pasos
- Configurar recepción de logs de seguridad en Windows
- Simular primer ataque y ver alerta en dashboard
- Documentar primer reporte de incidente completo


---
