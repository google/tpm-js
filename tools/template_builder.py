#!/usr/bin/env python2
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import sys
import jinja2


def main():
  parser = argparse.ArgumentParser(description="Renders jinja2 templates")
  parser.add_argument("dir", help="Templates directory")
  parser.add_argument(
      "input",
      help="Input template file - must be located in templates directory")
  parser.add_argument("output", help="Output rendered filename")
  args = parser.parse_args()
  env = jinja2.Environment(
      loader=jinja2.FileSystemLoader(args.dir), trim_blocks=True)
  file(args.output, 'w').write(env.get_template(args.input).render())


if __name__ == "__main__":
  sys.exit(main())
