from processor.packet_sniffer import PacketSniffer
from utils.network_utils import check_api_connection
from utils.auth import auth_manager
from utils.logger import setup_logger

def main():
    logger = setup_logger()
    
    try:
        auth_manager.refresh_tokens()
        logger.info("Successfully authenticated with the server")
    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}")
        return

    sniffer = PacketSniffer()
    try:
        sniffer.start_sniffing()
    except KeyboardInterrupt:
        print("Sniffing stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sniffer.process_remaining_flows()
        print("Exiting the program.")

if __name__ == "__main__":
    main()