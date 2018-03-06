import pickle, time
from bs4 import BeautifulSoup
import sys
import subprocess
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By


def dump_dom(url, dir_path):
	chrome_options = Options()  
	chrome_options.add_argument("--headless") 
	driver = webdriver.Chrome(executable_path="./chromedriver")
	driver.set_window_size(1920, 1500)
	driver.get("http://"+url)
	time.sleep(1.5)
	
	# save screenshot
	driver.save_screenshot(dir_path+"screenshots/"+url+".png")

	# save DOM
	html = driver.execute_script("return document.documentElement.outerHTML")
	dom_file = open( dir_path+"DOM/"+url+".html",'w')
	dom_file.write(html)
	dom_file.close()

	#save final URL
	final_url = open( dir_path+"final_urls/"+url,'w')
	final_url.write(str(driver.current_url))
	final_url.close()

	# save body text
	text = driver.find_elements(By.XPATH, '//body')[0].text
	text_file = open( dir_path+"text/"+url+".txt",'w')
	text_file.write(text)
	text_file.close()
	driver.close()

def main():
	results_dir = sys.argv[1]
	subprocess.call(["mkdir", results_dir+"screenshots", results_dir+"DOM", results_dir+"text", results_dir+"final_urls"])
	urls= [x.strip() for x in open("./hosts.txt").readlines()]

	for url in urls[:-1]:
		try:
			dump_dom(url, results_dir)
			print("SUCCESS: "+url)
		except:
			print("ERROR: "+url)
			continue



if __name__ == "__main__":
	main()

