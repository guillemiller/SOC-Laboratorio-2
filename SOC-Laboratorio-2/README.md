# SOC Laboratory 2 – Windows Security Event Investigation

## Descripción del proyecto

En este laboratorio trabajé con registros de seguridad de Windows utilizando Python para buscar actividades sospechosas, relacionar diferentes eventos y generar alertas que podrían ser útiles durante una investigación de nivel SOC Analyst L1.

Para realizar el ejercicio utilicé registros sintéticos correspondientes al equipo `WS-VENTAS-01`.

## Objetivos

El objetivo principal fue practicar la investigación de eventos de seguridad de Windows y entender cómo diferentes eventos pueden relacionarse entre sí.

Durante el laboratorio trabajé en:

- Análisis de eventos de seguridad de Windows.
- Identificación de intentos de inicio de sesión fallidos y exitosos.
- Detección de creación de cuentas locales y asignación de privilegios administrativos.
- Identificación de ejecución de PowerShell mediante comandos codificados.
- Detección de accesos a recursos compartidos e instalación de servicios.
- Correlación de eventos teniendo en cuenta el usuario y el momento en que ocurrieron.
- Generación automática de alertas e informes utilizando Python.

## Herramientas utilizadas

- **Python:** procesamiento, análisis y correlación de los registros.
- **CSV:** almacenamiento de los eventos y generación de alertas.
- **Windows Security Event IDs:** identificación y clasificación de las actividades.
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
| -------- | ----------- |
| 4624 | Inicio de sesión exitoso |
| 4625 | Inicio de sesión fallido |
| 4720 | Creación de cuenta de usuario |
| 4732 | Incorporación a un grupo local |
| 4688 | Creación de procesos |
| 4104 | Registro de bloques de script de PowerShell |
| 5140 | Acceso a recurso compartido de red |
| 4697 | Instalación de un servicio |

## Detecciones implementadas

El script analiza los registros y realiza diferentes comprobaciones, entre ellas:

1. Validación de las columnas y registros del archivo CSV.
2. Conteo y clasificación de los eventos según su Event ID.
3. Detección de intentos fallidos de autenticación seguidos de un inicio de sesión exitoso.
4. Identificación de cuentas creadas y posteriormente agregadas al grupo `Administrators`.
5. Detección de comandos PowerShell que utilizan `-EncodedCommand`.
6. Identificación de accesos a recursos compartidos.
7. Detección de instalación de nuevos servicios.
8. Correlación de eventos que ocurren después de la creación de cuentas con privilegios administrativos.
9. Asignación de una puntuación de riesgo basada en los eventos encontrados.
10. Generación automática de las alertas y del informe de investigación.

## Resultados de la investigación

En total se analizaron **19 eventos** y se encontraron **6 hallazgos**:

| Severidad | Cantidad |
| --------- | -------- |
| Alta | 5 |
| Media | 1 |
| **Total** | **6** |

### Principales hallazgos

Durante el análisis se encontraron los siguientes comportamientos:

- Dos intentos fallidos de autenticación seguidos de un inicio de sesión exitoso para `aramos`.
- Creación de la cuenta `soporte2` y posterior asignación de privilegios administrativos.
- Ejecución de PowerShell utilizando `-EncodedCommand`.
- Creación de la cuenta `backup_admin` y posterior asignación de privilegios administrativos.
- Acceso al recurso compartido `\\SRV-FILES\Documentos`.
- Instalación del servicio `RemoteAccessHelper`.

Estos eventos fueron analizados en conjunto para determinar si existía una relación temporal o una posible secuencia de actividad sospechosa.

### Puntuación de riesgo

Para este laboratorio utilicé una puntuación heurística basada en los eventos y comportamientos detectados:

| Cuenta | Puntuación | Nivel |
| ------------ | ---------- | ----- |
| soporte2 | 95 | Alto |
| backup_admin | 65 | Alto |
| aramos | 55 | Alto |
| admin | 10 | Bajo |

Las puntuaciones son **propias de este laboratorio y tienen fines educativos**. No representan una probabilidad real de compromiso ni utilizan una escala de riesgo estandarizada.

## Cómo ejecutar el laboratorio

### Requisitos

- Python 3.x
- Visual Studio Code (opcional)
- Windows

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

Este laboratorio me permitió practicar una investigación básica de seguridad utilizando eventos de Windows y Python.

A partir de los registros pude identificar diferentes comportamientos sospechosos, relacionar eventos por usuario y tiempo y generar alertas a partir de reglas definidas previamente.

El ejercicio representa un flujo de trabajo básico que puede aplicarse a algunas de las tareas que realiza un **SOC Analyst L1**, especialmente en el análisis inicial de eventos, la detección de comportamientos anómalos y la documentación de incidentes.

## Limitaciones

- Los registros utilizados son sintéticos y fueron creados únicamente con fines educativos.
- Las detecciones utilizan reglas y heurísticas simples.
- La presencia de un evento sospechoso no significa necesariamente que exista una actividad maliciosa.
- Las puntuaciones de riesgo no corresponden a un modelo de scoring validado.
- En un entorno real sería necesario contar con más información del endpoint, usuario, procesos, red y contexto del incidente antes de determinar si una actividad representa un compromiso real.

---

**Proyecto educativo de ciberseguridad – SOC Analyst L1 Portfolio**