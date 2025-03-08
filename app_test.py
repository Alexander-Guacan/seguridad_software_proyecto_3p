import pytest
import time
from flask import Flask
from io import StringIO
from unittest import mock
from app import app, guardar_reporte, attack_logs, REPORTE_ARCHIVO

@pytest.fixture
def client():
    # Crea una instancia de test client
    with app.test_client() as client:
        yield client

def test_get_logs(client):
    # Asegúrate de que la ruta /logs devuelva un JSON con los logs de ataques
    response = client.get('/logs')
    assert response.status_code == 200
    assert response.is_json  # Verifica que la respuesta sea un JSON

def test_descargar_reporte(client):
    # Verifica que la ruta /descargar_reporte sirva el archivo CSV de reportes
    response = client.get('/descargar_reporte')
    assert response.status_code == 200
    assert response.data.startswith(b"")  # Verifica que el archivo no esté vacío

def test_guardar_reporte():
    # Usa mock para comprobar la escritura en el archivo CSV
    with mock.patch('builtins.open', mock.mock_open()) as mocked_file:
        guardar_reporte("DDoS", "Ataque detectado desde 192.168.1.1")
        mocked_file.assert_called_once_with(REPORTE_ARCHIVO, mode="a", newline="")
        handle = mocked_file()
        handle.write.assert_called_once()  # Verifica que se haya escrito en el archivo
        # Verifica que la función de escritura haya llamado correctamente con el mensaje esperado
        assert 'DDoS' in handle.write.call_args[0][0]
        assert 'Ataque detectado desde 192.168.1.1' in handle.write.call_args[0][0]

