#!/usr/bin/env python3

import os
import json


INTER_1 = 'https://github.com/WAGO/pfc-firmware/releases/download/v3.1.7/WAGO_FW0750-8xxx_V030107_IX13_r40667.img'
INTER_2 = 'https://github.com/WAGO/pfc-firmware/releases/download/v03.09.04-21/WAGO_FW0750-8x0x_V030904_IX21_r65544.img'


def get_img_stats(img_url,docker_img_name):
	docker_resp = os.popen(f'docker run -v /dev:/dev -e IMG_URL="{img_url}" -it --privileged {docker_img_name}').read()
	return json.loads(docker_resp)

print(" * Loading Docker Image...")
docker_img_name = os.popen(f'docker load -i docker_artifact.tar').read().split('Loaded image ID: ')[1].strip()

print(" * Loading v3.1.7..")
old_stats = get_img_stats(INTER_1,docker_img_name)
old_total_sloc = old_stats['php_sloc'] + old_stats['js_sloc']
old_total_comp = old_stats['php_complexity'] + old_stats['js_complexity']
print(f"    > v3.1.7 firmware contained {old_total_sloc:,} total SLOC ({old_stats['js_sloc']:,} JS; {old_stats['php_sloc']:,} PHP) and an aggregate cyclomatic complexity score of {old_total_comp:,} ({old_stats['js_complexity']:,} JS; {old_stats['php_complexity']:,} PHP)")

print(" * Loading v3.09.04...")
new_stats = get_img_stats(INTER_2,docker_img_name)
new_total_sloc = new_stats['php_sloc'] + new_stats['js_sloc']
new_total_comp = new_stats['php_complexity'] + new_stats['js_complexity']
print(f"    > v3.09.04 contained {new_total_sloc:,} total SLOC ({new_stats['js_sloc']:,} JS; {new_stats['php_sloc']:,} PHP) and an aggregate cyclomatic complexity score of {new_total_comp:,} ({new_stats['js_complexity']:,} JS; {new_stats['php_complexity']:,} PHP)")


sloc_percent_change = int((new_total_sloc - old_total_sloc) / old_total_sloc * 100)
comp_percent_change = int((new_total_comp - old_total_comp) / old_total_comp * 100)
print(f"    > This data shows that from v3.1.7 to v3.09.04, the web application codebase has grown by over {sloc_percent_change:,}% and increased in complexity by over {comp_percent_change:,}%.")

print(" * Removing Docker Image...")
os.popen(f'docker rmi -f {docker_img_name}')

print(' * Done')