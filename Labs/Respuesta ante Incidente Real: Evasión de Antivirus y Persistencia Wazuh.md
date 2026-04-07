#  Reporte de Incidente de Seguridad — INC-001

---

## 1. ENCABEZADO

| Campo | Detalle |
|---|---|
| **ID Incidente** | INC-2026-002 |
| **Título** | Modificación maliciosa del archivo HOSTS — Bloqueo de McAfee |
| **Fecha de detección** | 06/04/2026 17:47 hs |
| **Fecha de cierre** | 06/04/2026 21:30 hs |
| **Analista** | Andres Busto |
| **Severidad** |  Alta |
| **Estado** | Contenido — Limpieza en proceso |
| **Plataforma de detección** | Wazuh SIEM — Rule ID 513 |
| **Agente afectado** | MartaTest — Windows 11 (192.168.XXX.51) |

---

## 2. RESUMEN EJECUTIVO

El día 06/04/2026, el SIEM Wazuh detectó una alerta de nivel 9 clasificada como "Windows malware detected" en el agente MartaTest (Windows 11). La investigación reveló que el archivo HOSTS del sistema había sido modificado para bloquear la comunicación del antivirus McAfee con sus servidores de actualización. El análisis forense posterior identificó un ejecutable malicioso (Updater.exe) instalado como parte de un bundle de TLauncher, con comportamiento asociado a técnicas de evasión de defensas, persistencia y posible captura de credenciales. Se procedió a contener la amenaza mediante cuarentena con Malwarebytes y eliminación de componentes maliciosos.

---

## 3. LÍNEA DE TIEMPO

| Hora | Evento |
|---|---|
| 17:47 | Wazuh genera alerta Rule ID 513 — Windows malware detected — Level 9 |
| 17:50 | Analista recibe y revisa la alerta en el dashboard |
| 17:52 | Se confirma modificación del archivo HOSTS |
| 17:55 | Se identifica IOC: `0.0.0.1 mssplus.mcafee.com` |
| 18:05 | Investigación de tareas programadas — se identifica Updater.exe |
| 18:15 | Hash de Updater.exe obtenido y verificado en VirusTotal |
| 18:20 | VirusTotal confirma comportamiento malicioso — 2/72 detecciones |
| 18:30 | Análisis MITRE ATT&CK — Input Capture, Process Injection confirmados |
| 18:40 | Execution Parents en VT confirman origen: TJprojMain.exe (TLauncher) |
| 18:50 | Malwarebytes instalado y scan ejecutado |
| 19:05 | Malwarebytes detecta 4 PUPs incluyendo TLauncher-Installer-1.8.8.exe |
| 19:10 | Cuarentena de 4 items ejecutada |
| 21:30 | Incidente documentado — limpieza manual en proceso |

---

## 4. ANÁLISIS TÉCNICO

### Alerta inicial
```
Rule ID:      513
Description:  Windows malware detected
Level:        9 (Alto)
Module:       rootcheck
File:         C:\Windows\System32\Drivers\etc\HOSTS
Title:        Windows Malware: Anti-virus site on the hosts file
```

> <img width="1335" height="347" alt="image" src="https://github.com/user-attachments/assets/b3cd2a3a-291a-45c5-8bdf-38af7ab9938c" />


---

### IOC — Indicadores de Compromiso

```
Tipo:          Modificación de archivo HOSTS
Archivo:       C:\Windows\System32\Drivers\etc\HOSTS
Entrada IOC:   0.0.0.1    mssplus.mcafee.com
Impacto:       McAfee bloqueado — sin comunicación con servidores
```

<img width="781" height="702" alt="image" src="https://github.com/user-attachments/assets/ce7a10b3-97b1-4888-ac67-3e9fd58aa119" />


---

### Ejecutable malicioso identificado

```
Archivo:        Updater.exe
Ruta:           C:\Program Files (x86)\Skillbrains\Updater\Updater.exe
Hash SHA256:    A5E3BDC3B0B0BD6455892E23008161B5478B24F4FE1801F43A8A01CFFF1BCBA7
Instalado:      20/09/2024 16:23:39
Detecciones VT: 2/72
Community Score: -28
```

<img width="1568" height="542" alt="image" src="https://github.com/user-attachments/assets/281e6668-8ea4-4640-890d-dd1044ded884" />


<img width="1568" height="700" alt="image" src="https://github.com/user-attachments/assets/89b6d9af-8202-4ef9-9bfa-ef5c37ea7861" />


---

### Clasificación MITRE ATT&CK


| Táctica | Técnica | ID | Evidencia |
|---|---|---|---|
| Execution | Scheduled Task/Job | T1053 | Creación de tareas update-S-1-5-21 y update-sys |
| Persistence | Scheduled Task/Job | T1053 | Persiste en el sistema tras reinicios |
| Persistence | Boot/Logon Autostart Execution | T1547 | Se ejecuta automáticamente al iniciar sesión |
| Defense Evasion | Masquerading | T1036 | Se camufla como updater legítimo de LightShot |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Bloquea McAfee modificando el archivo HOSTS — agrega `0.0.0.1 mssplus.mcafee.com` |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | detect-debug-environment confirmado en análisis VT |
| Credential Access | Input Capture | T1056 | Comportamiento de keylogger confirmado en sandbox VT |
| Discovery | System Information Discovery | T1082 | Recopilación de info del sistema confirmada en VT |
| Discovery | File and Directory Discovery | T1083 | Escaneo de archivos del sistema confirmado en VT |
| Collection | Input Capture | T1056 | Recolección de input del usuario |
| Command and Control | Application Layer Protocol | T1071 | 193 IPs contactadas confirmadas en análisis VT |

<img width="1568" height="655" alt="image" src="https://github.com/user-attachments/assets/f35646d4-8d35-42cc-812d-2b90fb38f6b2" />
<img width="1401" height="698" alt="image" src="https://github.com/user-attachments/assets/fe8e754d-ad8a-4a19-a970-352087902735" />


---

### Análisis de tareas programadas

Se identificaron dos tareas programadas maliciosas camufladas con nombres genéricos:

```
Tarea 1: update-S-1-5-21-785068007-406128360-3717506375-1002
         Ejecuta: C:\Program Files (x86)\Skillbrains\Updater\Updater.exe
         Frecuencia: Diaria a las 16:32

Tarea 2: update-sys
         Ejecuta: C:\Program Files (x86)\Skillbrains\Updater\Updater.exe
         Frecuencia: Diaria a las 17:19
```

<img width="1324" height="303" alt="image" src="https://github.com/user-attachments/assets/f67e9e12-71c6-4326-bc0b-c3d3f7c17f5e" />


---

### Confirmación del vector de infección

El análisis de Execution Parents en VirusTotal confirmó el origen:

```
TJprojMain.exe    → 63/68 detecciones ← Componente de TLauncher
                  → Padre directo del Updater.exe malicioso
                  → Asociado a Darkgate malware
```

Malwarebytes confirmó la presencia del instalador:
```
Archivo:  C:\USERS\User\DOWNLOADS\TLAUNCHER-INSTALLER-1.8.8.EXE
Tipo:     PUP.Optional.BundleInstaller
Hash:     5CBAE5501E6CC897884DC74BC7F563DE5E9D61F15AC6A3F082301344EE007FE7
```

<img width="1247" height="884" alt="image" src="https://github.com/user-attachments/assets/b4f19f71-eecc-4bb6-87fb-f085d8248ae0" />




<img width="838" height="403" alt="image" src="https://github.com/user-attachments/assets/22562306-149f-4c6d-96c1-84021707d3bc" />


---

### Cadena de infección completa

```
Usuario descarga TLauncher-Installer-1.8.8.exe
              ↓
TLauncher instala LightShot troyanizado como bundleware
              ↓
LightShot instala Updater.exe malicioso
(C:\Program Files (x86)\Skillbrains\Updater\)
              ↓
Updater.exe crea tareas programadas camufladas
(update-S-1-5-21 / update-sys)
              ↓
Modifica C:\Windows\System32\Drivers\etc\HOSTS
Agrega: 0.0.0.1 mssplus.mcafee.com
              ↓
McAfee queda sin comunicación con servidores
No puede actualizarse ni reportar amenazas
              ↓
Wazuh detecta la modificación del HOSTS ✅
```

---

### Archivos adicionales detectados por Malwarebytes

```
1. PUP.Optional.Softonic
   └── ZaraRadio-1.6.6-installer_II5-GZ1.exe
   └── C:\USERS\User\DOWNLOADS\

2. PUP.Optional.BundleInstaller
   └── DTLite1230-2352.exe (Daemon Tools)
   └── C:\USERS\User\DOWNLOADS\

3. PUP.Optional.BundleInstaller
   └── TLauncher-Installer-1.8.8.exe ← VECTOR PRINCIPAL
   └── C:\USERS\User\DOWNLOADS\

4. PUP.Optional.BundleInstaller
   └── ZaraRadio-1.6.6-installer_1W-9JA1.exe
   └── C:\USERS\User\DOWNLOADS\
```
<img width="1600" height="211" alt="image" src="https://github.com/user-attachments/assets/8a9c6a8b-0b83-4d31-a3a6-f8fc42ee22f3" />

---

## 5. ACCIONES TOMADAS

```
1. Identificación del IOC en archivo HOSTS
2. Hash de Updater.exe obtenido con Get-FileHash
3. Verificación en VirusTotal — comportamiento malicioso confirmado
4. Análisis de tareas programadas — identificadas 2 tareas maliciosas
5. Malwarebytes instalado y scan ejecutado
6. 4 items enviados a cuarentena por Malwarebytes
7. Intento de eliminación manual de carpeta Skillbrains
   └── Bloqueado por el proceso — pendiente reinicio
8. Usuarios notificados para cambio de contraseñas
```

---

## 6. CAUSA RAÍZ

La infección se originó por la descarga e instalación de **TLauncher**, un launcher no oficial de Minecraft, que incluía software bundled malicioso. El instalador aprovechó la falta de atención del usuario durante el proceso de instalación para instalar componentes adicionales no solicitados, incluyendo una versión troyanizada de LightShot que contenía el Updater.exe malicioso.

**Factor agravante:** La PC es compartida por múltiples usuarios con distintos niveles de conocimiento técnico, lo que aumenta el riesgo de instalación de software no autorizado.

---

## 7. RECOMENDACIONES

```
1. INMEDIATO
   └── Completar eliminación manual de C:\Program Files (x86)\Skillbrains\
   └── Eliminar tareas programadas maliciosas
   └── Limpiar archivo HOSTS
   └── Cambiar todas las contraseñas desde otro dispositivo
       (posible captura de credenciales — Input Capture T1056)

2. CORTO PLAZO
   └── Desinstalar TLauncher completamente
   └── Correr Malwarebytes Full Scan (no solo Threat Scan)
       con Rootkits habilitado
   └── Actualizar McAfee tras limpiar el HOSTS
   └── Revisar historial de navegación por actividad sospechosa

3. LARGO PLAZO
   └── Política de software autorizado para usuarios de la PC
   └── No descargar software de fuentes no oficiales
   └── Usar solo launchers oficiales (launcher.minecraft.net)
   └── Monitoreo continuo con Wazuh
   └── Considerar restricción de permisos de instalación
       para usuarios no administradores
```

---

## 8. LECCIONES APRENDIDAS

- **El SIEM detectó lo que el antivirus no pudo** porque el antivirus estaba bloqueado. Esto demuestra la importancia de tener múltiples capas de seguridad.
- **La investigación forense manual** fue clave para determinar la cadena completa de infección. La alerta inicial solo mostraba el síntoma, no la causa.
- **VirusTotal con análisis de Execution Parents** permitió confirmar el vector de infección y mapear la cadena completa.
- **Los PUPs son una amenaza real** y no deben subestimarse. Un software catalogado como "Potentially Unwanted" puede tener comportamiento equivalente a malware.
- **La seguridad en PCs compartidas** requiere políticas claras de uso y restricción de instalación de software.

---

## 9. EVIDENCIA

```
[ ] Captura dashboard Wazuh — Alerta Rule ID 513
[ ] Captura archivo HOSTS — IOC visible
[ ] Resultado VirusTotal — Updater.exe
[ ] Pestaña Behavior VirusTotal — MITRE ATT&CK
[ ] Execution Parents — TJprojMain.exe
[ ] Programador de tareas — Tareas maliciosas
[ ] Resultado Malwarebytes — 4 detecciones
[ ] Log completo de Malwarebytes
```

---

## 10. REFERENCIAS

| Recurso | URL |
|---|---|
| MITRE ATT&CK T1562 — Disable Security Tools | https://attack.mitre.org/techniques/T1562/ |
| MITRE ATT&CK T1056 — Input Capture | https://attack.mitre.org/techniques/T1056/ |
| MITRE ATT&CK T1053 — Scheduled Task | https://attack.mitre.org/techniques/T1053/ |
| MITRE ATT&CK T1036 — Masquerading | https://attack.mitre.org/techniques/T1036/ |
| VirusTotal — Hash Updater.exe | https://www.virustotal.com |
| Wazuh Rule 513 Documentation | https://documentation.wazuh.com |

---

## 11. HERRAMIENTAS UTILIZADAS

| Herramienta | Uso |
|---|---|
| Wazuh SIEM | Detección inicial de la amenaza |
| PowerShell | Análisis forense del sistema |
| Get-FileHash | Obtención de hash SHA256 |
| VirusTotal | Verificación de archivos sospechosos |
| Malwarebytes | Detección y cuarentena de PUPs |
| Task Scheduler | Análisis de persistencia |

---

*Reporte generado por: Andres Busto*
*Entorno: Laboratorio real — Wazuh + Windows 11*
*Fecha: 06/04/2026*
