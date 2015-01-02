#!/usr/bin/env python3
# License: BSD 3 clause
"""
Clone all projects from GitLab and recreate them on Stash

:author: Dan Blanchard (dblanchard@ets.org)
:organization: ETS
:date: June 2014
"""

import argparse
import getpass
import os
import re
import subprocess
import sys
import tempfile

import stashy
from gitlab import Gitlab as GitLabAPI

from mapping import namespace_to_project

__version__ = '0.1.0'


def get_gitlab_info(file='gitlab.csv'):
    import csv
    reader = csv.reader(open(file, 'r'))
    for i in reader:
        yield dict(namespace=dict(name=i[0]), name=i[1], ssh_url_to_repo=i[2], name_with_namespace=i[3])


def gen_all_results(method, per_page=20, *args, **kwargs):
    """
    Little helper function to generate all pages of results for a given method
    in one list.
    """
    get_more = True
    page_num = 0
    if 'page' in kwargs:
        kwargs.pop('page')
    while get_more:
        page_num += 1
        proj_page = method(*args, page=page_num, per_page=per_page, **kwargs)
        # proj_page will be False if method fails
        if proj_page:
            get_more = len(proj_page) == per_page
            yield iter(proj_page)
        else:
            get_more = False


def init_api_instance(args):
    # Setup authenticated GitLab and Stash instances
    if args.token:
        gitlab = GitLabAPI(args.gitlab_url, token=args.token,
                           verify_ssl=args.unverify_ssl)
    else:
        gitlab = None
    if not args.username:
        print('Username: ', end="", file=sys.stderr)
        args.username = input('').strip()
    if not args.password:
        args.password = getpass.getpass('Password: ')
    stash = stashy.connect(args.stash_url, args.username, args.password, args.unverify_ssl)
    if gitlab is None:
        gitlab = GitLabAPI(args.gitlab_url, verify_ssl=args.unverify_ssl)
        gitlab.login(args.username, args.password)
    return gitlab, stash


def get_or_create_stash_proj_key(key_set, names_to_keys, proj_name, stash, stash_project_names):
    # Create Stash project if it doesn't already exist
    if proj_name not in stash_project_names:
        # Create Stash project key
        key = proj_name
        if key.islower():
            key = key.title()
        key = re.sub(r'[^A-Z]', '', key)
        if len(key) < 2:
            key = re.sub(r'[^A-Za-z]', '', proj_name)[0:2].upper()
        added = False
        suffix = 65
        while key in key_set:
            if not added:
                key += 'A'
            else:
                suffix += 1
                key = key[:-1] + chr(suffix)
        key_set.add(key)

        # Actually add the project to Stash
        print('Creating Stash project "%s" with key %s...' %
              (proj_name, key), end="", file=sys.stderr)
        sys.stderr.flush()
        stash.projects.create(key, proj_name)
        names_to_keys[proj_name] = key
        stash_project_names.add(proj_name)
        print('done', file=sys.stderr)
        sys.stderr.flush()
    else:
        key = names_to_keys[proj_name]
    return key


def round_to_stash_repo_name(repo_name):
    if not repo_name[0].isalnum():
        repo_name = 'A ' + repo_name
    repo_name = re.sub(r'[^A-Za-z0-9 _.-]', ' ', repo_name)
    if len(repo_name) > 128:
        repo_name = repo_name[0:128]

    return repo_name


def create_stash_repo_if_not_exist(args, proj_name, repo_name, repo_to_slugs, skipped_count, stash_proj_key,
                                   stash_project):
    # Add repository to Stash project if it's not already there
    if repo_name not in repo_to_slugs[stash_proj_key]:
        print('Creating Stash repository "%s" in project "%s"...' %
              (repo_name, proj_name), end="", file=sys.stderr)
        sys.stderr.flush()
        stash_repo = stash_project.repos.create(repo_name)
        repo_to_slugs[stash_proj_key][repo_name] = stash_repo['slug']
        print('done', file=sys.stderr)
        sys.stderr.flush()
    elif args.skip_existing:
        print('Skipping existing Stash repository "%s" in project "%s"' %
              (repo_name, proj_name), file=sys.stderr)
        sys.stderr.flush()
        skipped_count += 1
        stash_repo = None
    else:
        print('Updating existing Stash repository "%s" in project "%s"' %
              (repo_name, proj_name), file=sys.stderr)
        sys.stderr.flush()
        repo_slug = repo_to_slugs[stash_proj_key][repo_name]
        stash_repo = stash_project.repos[repo_slug].get()
    return skipped_count, stash_repo


def push_to_stash(failed_to_clone, gitlab_proj, skipped_count, stash_repo_url, transfer_count):
    with tempfile.TemporaryDirectory() as temp_dir:
        cwd = os.getcwd()
        # Clone repository to temporary directory
        print('\nCloning GitLab repository...', file=sys.stderr)
        sys.stderr.flush()
        try:
            subprocess.check_call(['git', 'clone', '--mirror',
                                   gitlab_proj['ssh_url_to_repo'],
                                   temp_dir])
        except subprocess.CalledProcessError:
            print('Failed to clone GitLab repository. This usually when ' +
                  'it does not exist.', file=sys.stderr)
            failed_to_clone.add(gitlab_proj['name_with_namespace'])
            skipped_count += 1
            return skipped_count, transfer_count
        os.chdir(temp_dir)

        # Check that repository is not empty
        try:
            subprocess.check_call(['git', 'log', '--format=oneline', '-1'],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print('Repository is empty, so skipping push to Stash.',
                  file=sys.stderr)
            skipped_count += 1
        else:
            # Change remote to Stash and push
            print('\nPushing repository to Stash...', file=sys.stderr)
            sys.stderr.flush()
            subprocess.check_call(['git', 'remote', 'set-url', 'origin',
                                   stash_repo_url])
            subprocess.check_call(['git', 'push', '--mirror'])
            transfer_count += 1

        os.chdir(cwd)
    return skipped_count, transfer_count


def main(args):

    gitlab, stash = init_api_instance(args)

    print('Retrieving existing Stash projects...', end="", file=sys.stderr)
    sys.stderr.flush()
    key_set = {proj['key'] for proj in stash.projects}
    stash_project_names = {proj['name'] for proj in stash.projects}
    names_to_keys = {proj['name']: proj['key'] for proj in stash.projects}
    print('done', file=sys.stderr)
    sys.stderr.flush()

    updated_projects = set()
    repo_to_slugs = {}
    failed_to_clone = set()
    transfer_count = 0
    skipped_count = 0
    print('Processing GitLab projects...', file=sys.stderr)
    sys.stderr.flush()

    for gitlab_proj in get_gitlab_info():
        print('\n' + ('=' * 80) + '\n', file=sys.stderr)
        sys.stderr.flush()
        # mapping from GitLab namespace to Stash project
        proj_name = namespace_to_project[gitlab_proj['namespace']['name']]

        stash_proj_key = get_or_create_stash_proj_key(key_set, names_to_keys, proj_name, stash, stash_project_names)

        stash_project = stash.projects[stash_proj_key]

        # Initialize maping from repository names to slugs for later
        if stash_proj_key not in repo_to_slugs:
            repo_to_slugs[stash_proj_key] = {repo['name']: repo['slug'] for repo in stash_project.repos}

        # Create Stash-compatible name for repository
        # Repository names are limited to 128 characters.
        # They must start with a letter or number and may contain spaces,
        # hyphens, underscores and periods
        repo_name = round_to_stash_repo_name(gitlab_proj['name'])

        skipped_count, stash_repo = create_stash_repo_if_not_exist(args, proj_name, repo_name, repo_to_slugs,
                                                                   skipped_count, stash_proj_key, stash_project)
        if stash_repo is None:
            continue

        stash_repo_url = ""
        for clone_link in stash_repo['links']['clone']:
            if clone_link['name'] == 'ssh':
                stash_repo_url = clone_link['href']
                break

        skipped_count, transfer_count = push_to_stash(failed_to_clone, gitlab_proj, skipped_count, stash_repo_url,
                                                      transfer_count)

        updated_projects.add(proj_name)

    print('\n' + ('=' * 35) + 'SUMMARY' + ('=' * 35), file=sys.stderr)
    print('{} repositories transferred.\n'.format(transfer_count),
          file=sys.stderr)
    print('{} repositories skipped.\n'.format(skipped_count),
          file=sys.stderr)
    print('Projects created/updated:', file=sys.stderr)
    for proj in sorted(updated_projects):
        print('\t' + proj, file=sys.stderr)
    print('Repositories that we could not clone:', file=sys.stderr)
    for repo_name in sorted(failed_to_clone):
        print('\t' + repo_name, file=sys.stderr)


if __name__ == '__main__':
    # Get command line arguments
    parser = argparse.ArgumentParser(
        description="Transfer all projects/repositories from GitLab to Stash. \
                     Note: This script assumes you have your SSH key \
                     registered with both GitLab and Stash.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        conflict_handler='resolve')
    parser.add_argument('gitlab_url',
                        help='The full URL to your GitLab instance.')
    parser.add_argument('stash_url',
                        help='The full URL to your Stash instance.')
    parser.add_argument('-p', '--password',
                        help='The password to use to authenticate if token is \
                              not specified. If password and token are both \
                              unspecified, you will be prompted to enter a \
                              password.')
    parser.add_argument('-P', '--page_size',
                        help='When retrieving result from GitLab, how many \
                              results should be included in a given page?.',
                        type=int, default=20)
    parser.add_argument('-s', '--unverify_ssl',
                        help='Enable SSL certificate verification',
                        action='store_false')
    parser.add_argument('-S', '--skip_existing',
                        help='Do not update existing repositories and just \
                              skip them.',
                        action='store_true')
    parser.add_argument('-t', '--token',
                        help='The private GitLab API token to use for \
                              authentication. Either this or username and \
                              password must be set.')
    parser.add_argument('-u', '--username',
                        help='The username to use for authentication, if token\
                              is unspecified.')
    parser.add_argument('-v', '--verbose',
                        help='Print more status information. For every ' +
                             'additional time this flag is specified, ' +
                             'output gets more verbose.',
                        default=0, action='count')
    parser.add_argument('--version', action='version',
                        version='%(prog)s {0}'.format(__version__))
    arguments = parser.parse_args()
    arguments.page_size = max(100, arguments.page_size)
    main(arguments)
