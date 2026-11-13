import csv
from datetime import datetime
# 1. Abrir y leer el archivo CSV

expected_columns = [
    "timestamp",
    "event_id",
    "computer",
    "username",
    "source_ip",
    "event_description",
    "details"
]

with open("windows_events.csv", "r", encoding="utf-8-sig", newline="") as file:
    reader = csv.DictReader(file)

    print("COLUMNAS DETECTADAS:", reader.fieldnames)

    if reader.fieldnames != expected_columns:
        raise ValueError("ERROR: Las columnas del CSV no coinciden.")

    events = [
        event for event in reader
        if event and any(value and value.strip() for value in event.values())
    ]

# 2. Validar los registros
for number, event in enumerate(events, start=2):
    if None in event or any(value is None for value in event.values()):
        raise ValueError(f"ERROR: Registro incompleto en la fila {number}.")

print("VALIDACION DEL CSV: CORRECTA")
print("Total de registros:", len(events))

# Detectar instalacion de servicios de Windows

print("\n=== ALERTAS: SERVICIOS INSTALADOS ===")

for event in events:

    if event["event_id"] == "4697":

        details = event["details"]

        service_name = details.replace("Service:", "").strip()

        print("\nALERTA: Nuevo servicio instalado")
        print("Fecha:", event["timestamp"])
        print("Equipo:", event["computer"])
        print("Usuario responsable:", event["username"])
        print("Nombre del servicio:", service_name)

for event in events:
    if event["event_id"] == "4697":
        print(event)
# 2. Mostrar información general
print("=== LABORATORIO 2: EVENTOS DE WINDOWS ===")

print("Total de eventos registrados:", len(events))

# 3. Contar los eventos por Event ID
print("\n=== EVENTOS POR ID ===")

event_counts = {}

for event in events:
    event_id = event["event_id"]

    if event_id not in event_counts:
        event_counts[event_id] = 0

    event_counts[event_id] += 1

for event_id, count in event_counts.items():
    print(f"Evento {event_id}: {count} registro(s)")

# 4. Mostrar los registros leídos
print("\n=== REGISTROS LEÍDOS ===")

for event in events:
    print(
        event["timestamp"],
        "| Event ID:", event["event_id"],
        "| Usuario:", event["username"],
        "| Equipo:", event["computer"]
    )
 # 5. Detectar creacion de cuentas administrativas

print("\n=== ALERTAS: CUENTAS ADMINISTRATIVAS ===")

for event in events:

    if event["event_id"] == "4732":

        if "Administrators" in event["details"]:

            print("\nALERTA: Modificacion de grupo administrativo")
            print("Fecha:", event["timestamp"])
            print("Equipo:", event["computer"])
            print("Usuario que realizo la accion:", event["username"])
            print("Detalle:", event["details"])
# 6. Detectar creacion de cuentas

print("\n=== ALERTAS: CREACION DE CUENTAS ===")

for event in events:

    if event["event_id"] == "4720":

        print("\nALERTA: Nueva cuenta creada")
        print("Fecha:", event["timestamp"])
        print("Equipo:", event["computer"])
        print("Actor:", event["username"])
        print("Detalle:", event["details"])


# 7. Correlacionar cuentas y privilegios con validacion temporal

print("\n=== INVESTIGACION CRONOLOGICA DE CUENTAS ===")

created_accounts = {}

# Primera pasada: identificar cuentas creadas
for event in events:

    if event["event_id"] == "4720":

        details = event["details"]

        if "New account:" in details:

            account = details.split("New account:")[1].strip()

            creation_time = datetime.strptime(
                event["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            created_accounts[account] = {
                "actor": event["username"],
                "computer": event["computer"],
                "timestamp": event["timestamp"],
                "creation_time": creation_time,
                "administrator": False,
                "privilege_actor": None,
                "privilege_timestamp": None
            }

# Segunda pasada: comprobar asignacion de privilegios
for event in events:

    if event["event_id"] == "4732":

        details = event["details"]

        if "Administrators" in details and "Account:" in details:

            account = details.split("Account:")[1].split(";")[0].strip()

            if account in created_accounts:

                privilege_time = datetime.strptime(
                    event["timestamp"],
                    "%Y-%m-%d %H:%M:%S"
                )

                creation_time = created_accounts[account]["creation_time"]

                # Comprobar que el privilegio se asigno despues de crear la cuenta
                if privilege_time > creation_time:

                    created_accounts[account]["administrator"] = True
                    created_accounts[account]["privilege_actor"] = event["username"]
                    created_accounts[account]["privilege_timestamp"] = event["timestamp"]

# Mostrar resultados
for account, info in created_accounts.items():

    print("\nCuenta:", account)
    print("Creada por:", info["actor"])
    print("Fecha de creacion:", info["timestamp"])

    if info["administrator"]:

        print("Privilegios administrativos: SI")
        print("Asignados por:", info["privilege_actor"])
        print("Fecha de asignacion:", info["privilege_timestamp"])

    else:

        print("Privilegios administrativos: NO")

# 8. Investigar actividad posterior de cuentas administrativas

print("\n=== ACTIVIDAD POSTERIOR DE CUENTAS ADMINISTRATIVAS ===")

for account, info in created_accounts.items():

    if info["administrator"]:

        print(f"\nCuenta investigada: {account}")

        for event in events:

            if event["username"] == account:

                if event["event_id"] in ["4624", "4688", "5140", "4697"]:

                    print(
                        event["timestamp"],
                        "| Evento:", event["event_id"],
                        "| Actividad:", event["event_description"],
                        "| Detalle:", event["details"]
                    )
# 9. Detectar indicadores de actividad sospechosa

print("\n=== INDICADORES DE ACTIVIDAD SOSPECHOSA ===")

for account, info in created_accounts.items():

    if info["administrator"]:

        for event in events:

            if event["username"] == account:

                details = event["details"].lower()

                if "-encodedcommand" in details:
                    print("\nALERTA: PowerShell con comando codificado")
                    print("Cuenta:", account)
                    print("Fecha:", event["timestamp"])
                    print("Detalle:", event["details"])

                if event["event_id"] == "5140":
                    print("\nALERTA: Acceso a recurso compartido")
                    print("Cuenta:", account)
                    print("Fecha:", event["timestamp"])
                    print("Detalle:", event["details"])

                if event["event_id"] == "4697":
                    print("\nALERTA: Instalacion de servicio")
                    print("Cuenta:", account)
                    print("Fecha:", event["timestamp"])
                    print("Detalle:", event["details"])



# 10. CLASIFICAR HALLAZGOS Y GENERAR INFORME SOC

print("\n=== CLASIFICACION DE HALLAZGOS ===")

findings = []
# Preparar fechas para las correlaciones temporales
for event in events:
    event["datetime"] = datetime.strptime(
        event["timestamp"],
        "%Y-%m-%d %H:%M:%S"
    )
# Detectar autenticacion sospechosa
for success in events:
    if success["event_id"] != "4624":
        continue

    previous_failures = [
        failure for failure in events
        if failure["event_id"] == "4625"
        and failure["username"] == success["username"]
        and failure["source_ip"] == success["source_ip"]
        and failure["datetime"] < success["datetime"]
        and (success["datetime"] - failure["datetime"]).total_seconds() <= 600
    ]

    if len(previous_failures) >= 2:
        findings.append({
            "severity": "ALTA",
            "account": success["username"],
            "timestamp": success["timestamp"],
            "description": (
                f"{len(previous_failures)} intentos fallidos "
                "seguidos de un inicio de sesion exitoso"
            )
        })

# Detectar creacion de cuentas administrativas
for account, info in created_accounts.items():

    if info["administrator"]:
        findings.append({
            "severity": "ALTA",
            "account": account,
            "timestamp": info["timestamp"],
            "description": (
                f"Creacion de cuenta con privilegios administrativos. "
                f"Cuenta creada por: {info['actor']}"
            )
        })

# Detectar actividades sospechosas posteriores
for event in events:
    username = event["username"]
    details = event["details"].lower()

    if event["event_id"] == "4688" and "-encodedcommand" in details:
        findings.append({
            "severity": "ALTA",
            "account": username,
            "timestamp": event["timestamp"],
            "description": "Ejecucion de PowerShell con comando codificado"
        })

    elif event["event_id"] == "4697":
        findings.append({
            "severity": "ALTA",
            "account": username,
            "timestamp": event["timestamp"],
            "description": "Instalacion de un servicio de Windows"
        })

    elif event["event_id"] == "5140":
        findings.append({
            "severity": "MEDIA",
            "account": username,
            "timestamp": event["timestamp"],
            "description": "Acceso a un recurso compartido de red"
        })

# Ordenar hallazgos por fecha
findings.sort(key=lambda finding: finding["timestamp"])

# Mostrar hallazgos
for finding in findings:
    print("\nSeveridad:", finding["severity"])
    print("Cuenta:", finding["account"])
    print("Fecha:", finding["timestamp"])
    print("Descripcion:", finding["description"])

# Calcular resumen
high_count = sum(1 for f in findings if f["severity"] == "ALTA")
medium_count = sum(1 for f in findings if f["severity"] == "MEDIA")

print("\n=== RESUMEN ===")
print("Hallazgos de severidad alta:", high_count)
print("Hallazgos de severidad media:", medium_count)
print("Total de hallazgos:", len(findings))


# 11. GENERAR INFORME AUTOMATICO

print("\n=== GENERANDO INFORME SOC ===")

with open("incident_report.txt", "w", encoding="utf-8") as report:

    report.write("INFORME DE INVESTIGACION SOC\n")
    report.write("============================\n\n")

    report.write("1. INFORMACION GENERAL\n")
    report.write("----------------------\n")
    report.write("Equipo investigado: WS-VENTAS-01\n")
    report.write(f"Total de eventos analizados: {len(events)}\n")
    report.write(f"Cuentas creadas investigadas: {len(created_accounts)}\n\n")

    report.write("2. RESUMEN EJECUTIVO\n")
    report.write("--------------------\n")
    report.write(f"Hallazgos de severidad alta: {high_count}\n")
    report.write(f"Hallazgos de severidad media: {medium_count}\n")
    report.write(f"Total de hallazgos: {len(findings)}\n\n")

    report.write("3. HALLAZGOS DETECTADOS\n")
    report.write("-----------------------\n")

    for finding in findings:
        report.write(f"\nSeveridad: {finding['severity']}\n")
        report.write(f"Cuenta: {finding['account']}\n")
        report.write(f"Fecha: {finding['timestamp']}\n")
        report.write(f"Descripcion: {finding['description']}\n")

    report.write("\n4. CRONOLOGIA DE EVENTOS\n")
    report.write("=======================\n")

    for event in sorted(
        events,
        key=lambda e: datetime.strptime(
            e["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )
    ):
        report.write(
            f"{event['timestamp']} | "
            f"ID: {event['event_id']} | "
            f"Usuario: {event['username']} | "
            f"Actividad: {event['event_description']} | "
            f"Detalle: {event['details']}\n"
        )

    report.write("\n5. CONCLUSION PRELIMINAR\n")
    report.write("-----------------------\n")
    report.write(
        "Se identificaron actividades que requieren investigacion adicional, "
        "incluyendo intentos fallidos de autenticacion seguidos de un acceso "
        "exitoso, creacion de cuentas con privilegios administrativos, "
        "ejecucion de PowerShell con comando codificado e instalacion de un "
        "servicio de Windows. Los registros disponibles no permiten confirmar "
        "por si solos un compromiso del sistema.\n"
    )

    report.write("\n6. LIMITACIONES DE LA INVESTIGACION\n")
    report.write("-----------------------------------\n")
    report.write(
        "El analisis se realizo sobre registros sinteticos de laboratorio. "
        "La presencia de un evento o indicador sospechoso no demuestra por "
        "si sola actividad maliciosa. Se requiere validar el contexto, "
        "la legitimidad de las acciones y evidencia adicional del sistema.\n"
    )

print("Informe generado: incident_report.txt")


# 12. Construir una cronologia de eventos

print("\n=== CRONOLOGIA DE INVESTIGACION ===")

# Ordenar eventos cronologicamente
sorted_events = sorted(
    events,
    key=lambda event: datetime.strptime(
        event["timestamp"],
        "%Y-%m-%d %H:%M:%S"
    )
)

for event in sorted_events:

    print(
        event["timestamp"],
        "| ID:", event["event_id"],
        "| Usuario:", event["username"],
        "| Actividad:", event["event_description"],
        "| Detalle:", event["details"]
    )
# 13. Verificar instalacion de servicios

print("\n=== SERVICIOS INSTALADOS ===")

for event in events:
    if event["event_id"] == "4697":
        print("Fecha:", event["timestamp"])
        print("Equipo:", event["computer"])
        print("Usuario:", event["username"])
        print("Servicio:", event["details"])



# 13. CORRELACION AUTOMATICA DE CUENTAS

print("\n=== CORRELACION AUTOMATICA DE CUENTAS ===")

created_accounts = {}

# Primera pasada: identificar las cuentas creadas
for event in events:

    if event["event_id"] == "4720":

        details = event["details"]

        if "New account:" in details:

            account = details.split("New account:")[1].strip()

            created_accounts[account] = {
                "creator": event["username"],
                "computer": event["computer"],
                "created_at": datetime.strptime(
                    event["timestamp"], "%Y-%m-%d %H:%M:%S"
                ),
                "admin": False,
                "admin_actor": None,
                "admin_at": None
            }


# Segunda pasada: comprobar asignaciones administrativas
for event in events:

    if event["event_id"] == "4732":

        details = event["details"]

        if "Administrators" in details and "Account:" in details:

            account = details.split("Account:")[1].split(";")[0].strip()

            if account in created_accounts:

                event_time = datetime.strptime(
                    event["timestamp"], "%Y-%m-%d %H:%M:%S"
                )

                if event_time >= created_accounts[account]["created_at"]:

                    created_accounts[account]["admin"] = True
                    created_accounts[account]["admin_actor"] = event["username"]
                    created_accounts[account]["admin_at"] = event_time


# Tercera pasada: mostrar el análisis de cada cuenta
for account, info in created_accounts.items():

    print("\n--------------------------------")
    print("CUENTA INVESTIGADA:", account)
    print("Creada por:", info["creator"])
    print("Equipo:", info["computer"])
    print("Fecha de creacion:", info["created_at"])

    if info["admin"]:

        print("Privilegios administrativos: SI")
        print("Privilegios otorgados por:", info["admin_actor"])
        print("Fecha de asignacion:", info["admin_at"])

        print("\nACTIVIDADES POSTERIORES:")

        for event in sorted(events, key=lambda e: e["timestamp"]):

            event_time = datetime.strptime(
                event["timestamp"], "%Y-%m-%d %H:%M:%S"
            )

            if (
                event["username"] == account
                and event_time >= info["admin_at"]
            ):

                print(
                    event["timestamp"],
                    "| Evento:", event["event_id"],
                    "| Actividad:", event["event_description"],
                    "| Detalle:", event["details"]
                )

    else:

        print("Privilegios administrativos: NO detectados")


# 8. CORRELACION TEMPORAL DE EVENTOS

print("\n=== CORRELACION TEMPORAL DE EVENTOS ===")

# Convertir las fechas de texto a objetos datetime
for event in events:
    event["datetime"] = datetime.strptime(
        event["timestamp"],
        "%Y-%m-%d %H:%M:%S"
    )

# Ordenar los eventos cronologicamente
events.sort(key=lambda event: event["datetime"])


# 8.1 Detectar varios fallos seguidos de un acceso exitoso

print("\n--- AUTENTICACION SOSPECHOSA ---")

for success in events:

    if success["event_id"] != "4624":
        continue

    previous_failures = []

    for failure in events:

        if failure["event_id"] != "4625":
            continue

        same_user = failure["username"] == success["username"]
        same_ip = failure["source_ip"] == success["source_ip"]
        before_success = failure["datetime"] < success["datetime"]

        if same_user and same_ip and before_success:

            difference = (
                success["datetime"] - failure["datetime"]
            ).total_seconds()

            if difference <= 600:
                previous_failures.append(failure)

    if len(previous_failures) >= 2:

        print("\nALERTA: Fallos seguidos de acceso exitoso")
        print("Usuario:", success["username"])
        print("IP de origen:", success["source_ip"])
        print("Intentos fallidos:", len(previous_failures))
        print("Acceso exitoso:", success["timestamp"])


# 8.2 Correlacionar creacion y asignacion de privilegios

print("\n--- ESCALADA DE PRIVILEGIOS ---")

for creation in events:

    if creation["event_id"] != "4720":
        continue

    details = creation["details"]

    if "New account:" not in details:
        continue

    account = details.split("New account:")[1].strip()

    for privilege in events:

        if privilege["event_id"] != "4732":
            continue

        privilege_details = privilege["details"]

        if "Account:" not in privilege_details:
            continue

        assigned_account = (
            privilege_details.split("Account:")[1]
            .split(";")[0].strip()
        )

        if assigned_account != account:
            continue

        if "Administrators" not in privilege_details:
            continue

        if privilege["datetime"] < creation["datetime"]:
            continue

        difference = (
            privilege["datetime"] - creation["datetime"]
        ).total_seconds()

        if difference <= 600:

            print("\nALERTA: Cuenta creada y elevada a administradora")
            print("Cuenta:", account)
            print("Creada por:", creation["username"])
            print("Fecha de creacion:", creation["timestamp"])
            print("Privilegios asignados:", privilege["timestamp"])


# 8.3 Detectar instalacion de servicio despues de un inicio de sesion

print("\n--- ACTIVIDAD POSTERIOR AL ACCESO ---")

for service in events:

    if service["event_id"] != "4697":
        continue

    for login in events:

        if login["event_id"] != "4624":
            continue

        if login["username"] != service["username"]:
            continue

        if login["datetime"] > service["datetime"]:
            continue

        difference = (
            service["datetime"] - login["datetime"]
        ).total_seconds()

        if difference <= 1800:

            print("\nALERTA: Servicio instalado despues del acceso")
            print("Usuario:", service["username"])
            print("Inicio de sesion:", login["timestamp"])
            print("Instalacion del servicio:", service["timestamp"])
            print("Detalle:", service["details"])
# ANALISIS DE SERVICIOS SOSPECHOSOS

print("\n=== ANALISIS DE SERVICIOS SOSPECHOSOS ===")

suspicious_services = [
    "RemoteAccessHelper",
    "RemoteSupport",
    "SystemUpdate"
]

for event in events:

    if event["event_id"] == "4697":

        details = event["details"]

        for service in suspicious_services:

            if service.lower() in details.lower():

                print("\nALERTA: Servicio potencialmente sospechoso")
                print("Servicio:", service)
                print("Fecha:", event["timestamp"])
                print("Equipo:", event["computer"])
                print("Usuario:", event["username"])
                print("Detalle:", details)
# === PUNTUACION DE RIESGO POR CUENTA ===

print("\n=== PUNTUACION DE RIESGO POR CUENTA ===")

risk_scores = {}
risk_reasons = {}
failed_logons = {}

def add_risk(username, points, reason):
    if not username:
        return

    if username not in risk_scores:
        risk_scores[username] = 0
        risk_reasons[username] = []

    risk_scores[username] += points
    risk_reasons[username].append(f"+{points} puntos: {reason}")


# Analizar los eventos en orden cronologico
for event in events:

    event_id = event["event_id"]
    username = event["username"].strip()
    source_ip = event["source_ip"].strip()
    details = event["details"]

    # 1. Intentos fallidos de autenticacion
    if event_id == "4625":
        key = (username, source_ip)

        failed_logons[key] = failed_logons.get(key, 0) + 1

        add_risk(
            username,
            5,
            "Intento fallido de autenticacion"
        )

    # 2. Inicio de sesion exitoso despues de fallos
    elif event_id == "4624":
        key = (username, source_ip)

        if failed_logons.get(key, 0) > 0:
            add_risk(
                username,
                25,
                "Inicio de sesion exitoso despues de intentos fallidos"
            )

    # 3. Creacion de cuentas
    elif event_id == "4720":
        add_risk(
            username,
            10,
            "Creacion de una cuenta por este usuario"
        )

    # 4. Asignacion de privilegios administrativos
    elif event_id == "4732":

        add_risk(
            username,
            10,
            "Agrego una cuenta a un grupo local"
        )

        if "Administrators" in details and "Account:" in details:
            target_account = details.split("Account:")[1].split(";")[0].strip()

            add_risk(
                target_account,
                25,
                "Cuenta incorporada al grupo Administrators"
            )

    # 5. Ejecucion de PowerShell con comando codificado
    elif event_id == "4688" and "-EncodedCommand" in details:
        add_risk(
            username,
            30,
            "Ejecucion de PowerShell con comando codificado"
        )

    # 6. Creacion de usuarios mediante PowerShell
    elif event_id == "4104" and "New-LocalUser" in details:
        add_risk(
            username,
            20,
            "Uso de PowerShell para crear una cuenta local"
        )

    # 7. Acceso a recursos compartidos
    elif event_id == "5140":
        add_risk(
            username,
            10,
            "Acceso a un recurso compartido"
        )

    # 8. Instalacion de servicios
    elif event_id == "4697":
        add_risk(
            username,
            30,
            "Instalacion de un servicio"
        )


# Mostrar puntuaciones
for username, score in sorted(
    risk_scores.items(),
    key=lambda item: item[1],
    reverse=True
):

    if score >= 50:
        level = "ALTO"
    elif score >= 25:
        level = "MEDIO"
    else:
        level = "BAJO"

    print("\n--------------------------------")
    print("CUENTA:", username)
    print("PUNTUACION:", score)
    print("NIVEL DE RIESGO:", level)
    print("MOTIVOS:")

    for reason in risk_reasons[username]:
        print("-", reason)
# === EXPORTAR ALERTAS A CSV ===

import csv

with open("alertas_soc.csv", "w", encoding="utf-8-sig", newline="") as file:

    writer = csv.writer(file)

    # Encabezados del archivo
    writer.writerow([
        "Fecha",
        "Cuenta",
        "Event ID",
        "Severidad",
        "Puntuacion",
        "Descripcion"
    ])


    # Recorrer los eventos registrados
    for event in events:

        event_id = event["event_id"]
        username = event["username"].strip()
        details = event["details"]

        # Detectar eventos que requieren investigacion
        if event_id in ["4625", "4720", "4732", "5140", "4697"] or (
            event_id == "4688" and "-encodedcommand" in details.lower()
        ):

            score = risk_scores.get(username, 0)

            # Clasificar la severidad segun el tipo de evento
            if event_id == "4625":
                severity = "MEDIA"

            elif event_id in ["4720", "4732", "4697"]:
                severity = "ALTA"

            elif event_id == "4688" and "-encodedcommand" in details.lower():
                severity = "ALTA"

            elif event_id == "5140":
                severity = "MEDIA"

            else:
                severity = "BAJA"

            # Guardar la alerta en el CSV
            writer.writerow([
                event["timestamp"],
                username,
                event_id,
                severity,
                score,
                details
            ])

print("\nArchivo alertas_soc.csv generado correctamente.")
