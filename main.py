from dominio.servico_chat import ServicoChat
from infraestrutura.rede import RedeServidor

if __name__ == "__main__":
    # Instancia o serviço de regras de negócio/roteamento
    servico = ServicoChat()

    # Instancia o servidor de rede passando a camada de serviço
    servidor = RedeServidor(
        servico_chat=servico, host="127.0.0.1", port=5000
    )

    # Inicia a escuta de conexões
    servidor.iniciar()