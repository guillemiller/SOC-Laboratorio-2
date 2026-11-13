# SOC Laboratory 2 – Windows Security Event Investigation

## Descripción del proyecto

En este laboratorio trabajé con registros de eventos de Windows utilizando Python para identificar actividades sospechosas, correlacionar diferentes eventos y generar alertas que podrían ser útiles durante una investigación de nivel SOC Analyst L1.

Para realizar el ejercicio utilicé registros sintéticos correspondientes al equipo `WS-VENTAS-01`.

## Objetivos

El objetivo principal fue practicar la investigación de eventos de Windows y comprender cómo diferentes actividades pueden relacionarse entre sí.

Durante el laboratorio trabajé en:

- Análisis de eventos de Windows.
- Identificación de intentos de inicio de sesión fallidos y exitosos.
- Detección de creación de cuentas locales y asignación de privilegios administrativos.
- Identificación de ejecución de PowerShell mediante comandos codificados.
- Detección de accesos a recursos compartidos e instalación de servicios.
- Correlación de eventos teniendo en cuenta el usuario y el momento en que ocurrieron.
- Generación automática de alertas e informes utilizando Python.

## Herramientas utilizadas

- **Python:** procesamiento, análisis y correlación de registros.
- **CSV:** almacenamiento de eventos y generación de alertas.
- **Windows Event IDs:** identificación y clasificación de actividades.
- **Visual Studio Code:** desarrollo y ejecución del script.

El proyecto utiliza únicamente módulos incluidos en la biblioteca estándar de Python, por lo que no es necesario instalar librerías externas.

## Estructura del proyecto

```text
SOC-Laboratorio-2/
│
├── windows_events.csv
├── investigate_windows.py
├── incident_report.txt
├── alertas_soc.csv
└── README.md
```

## Eventos analizados

| Event ID | Descripción |
|---|---|
| 4624 | Inicio de sesión exitoso |
| 4625 | Inicio de sesión fallido |
| 4720 | Creación de cuenta de usuario |
| 4732 | Incorporación a un grupo local |
| 4688 | Creación de procesos |
| 4104 | Registro de bloques de script de PowerShell |
| 5140 | Acceso a recurso compartido de red |
| 4697 | Instalación de un servicio |

## Detecciones implementadas

El script analiza los registros y realiza diferentes comprobaciones:

1. Validación de las columnas y registros del archivo CSV.
2. Conteo y clasificación de eventos según su Event ID.
3. Detección de intentos fallidos de autenticación seguidos de un inicio de sesión exitoso.
4. Identificación de cuentas creadas y posteriormente agregadas al grupo `Administrators`.
5. Detección de comandos PowerShell que utilizan `-EncodedCommand`.
6. Identificación de accesos a recursos compartidos.
7. Detección de instalación de nuevos servicios.
8. Correlación temporal de actividades posteriores a la creación de cuentas administrativas.
9. Asignación de puntuaciones de riesgo mediante reglas heurísticas.
10. Generación automática de alertas e informe de investigación.

## Resultados de la investigación

Se analizaron **19 eventos** y se identificaron **6 hallazgos** durante la investigación.

| Severidad | Cantidad |
|---|---:|
| Alta | 5 |
| Media | 1 |
| **Total** | **6** |

### Principales hallazgos

Durante el análisis se identificaron los siguientes comportamientos:

- Dos intentos fallidos de autenticación seguidos de un inicio de sesión exitoso para `aramos`.
- Creación de la cuenta `soporte2` y posterior asignación de privilegios administrativos.
- Ejecución de PowerShell utilizando `-EncodedCommand`.
- Creación de la cuenta `backup_admin` y posterior asignación de privilegios administrativos.
- Acceso al recurso compartido `\\SRV-FILES\Documentos`.
- Instalación del servicio `RemoteAccessHelper`.

Estos eventos fueron analizados en conjunto para identificar relaciones temporales y posibles secuencias de actividad sospechosa.

### Clasificación de alertas

El archivo `alertas_soc.csv` contiene alertas individuales clasificadas según el tipo de evento:

| Event ID / Actividad | Severidad asignada |
|---|---|
| 4625 – Inicio de sesión fallido | Media |
| 4720 – Creación de cuenta | Alta |
| 4732 – Incorporación a grupo local | Alta |
| 4688 – PowerShell con `-EncodedCommand` | Alta |
| 5140 – Acceso a recurso compartido | Media |
| 4697 – Instalación de servicio | Alta |

Esta clasificación corresponde a las reglas definidas para cada tipo de alerta. No debe confundirse con el resumen de hallazgos del informe, que agrupa comportamientos relacionados durante la investigación.

### Puntuación de riesgo

Para este laboratorio implementé una puntuación heurística basada en los eventos y comportamientos detectados.

| Cuenta | Puntuación | Nivel |
|---|---:|---|
| soporte2 | 95 | Alto |
| backup_admin | 65 | Alto |
| aramos | 55 | Alto |
| admin | 10 | Bajo |

La puntuación representa un valor acumulado por cuenta según las reglas implementadas. Por lo tanto, puede repetirse en distintas alertas de un mismo usuario.

Estas puntuaciones son propias del laboratorio y tienen fines educativos. No representan una probabilidad real de compromiso ni utilizan una escala de riesgo estandarizada.

## Cómo ejecutar el laboratorio

### Requisitos

- Python 3.x
- Windows
- Visual Studio Code (opcional)

### Ejecución

1. Descargar o clonar el repositorio.
2. Abrir la carpeta del proyecto.
3. Ejecutar el siguiente comando desde una terminal:

```bash
python investigate_windows.py
```

El script procesa el archivo `windows_events.csv` y genera automáticamente:

- `incident_report.txt`
- `alertas_soc.csv`

## Conclusión

Este laboratorio me permitió practicar una investigación básica de eventos de Windows utilizando Python.

A partir de los registros pude identificar comportamientos sospechosos, relacionar eventos por usuario y tiempo, aplicar reglas de detección y generar alertas e informes.

El ejercicio representa un flujo de trabajo básico relacionado con algunas de las tareas de un **SOC Analyst L1**, especialmente el análisis inicial de eventos, la identificación de comportamientos anómalos y la documentación de hallazgos.

## Limitaciones

- Los registros utilizados son sintéticos y fueron creados únicamente con fines educativos.
- Las direcciones IP pertenecen a rangos reservados para documentación y no representan equipos reales.
- Las detecciones utilizan reglas y heurísticas simples.
- La presencia de un evento sospechoso no demuestra necesariamente una actividad maliciosa.
- Las puntuaciones de riesgo no corresponden a un modelo de scoring validado.
- En un entorno real sería necesario contar con información adicional del endpoint, usuario, procesos, red y contexto del incidente antes de determinar si existe un compromiso.

---

**Proyecto educativo de ciberseguridad – SOC Analyst L1 Portfolio**
