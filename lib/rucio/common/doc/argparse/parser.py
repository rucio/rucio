from argparse import _HelpAction, _SubParsersAction, _StoreConstAction
import re


class NavigationException(Exception):
    pass


def parser_navigate(parser_result, path, current_path=None):
    if isinstance(path, str):
        if path == '':
            return parser_result
        path = re.split(r'\s+', path)
    current_path = current_path or []
    if len(path) == 0:
        return parser_result
    if 'children' not in parser_result:
        raise NavigationException(
            'Current parser has no child elements.  (path: %s)' %
            ' '.join(current_path))
    next_hop = path.pop(0)
    for child in parser_result['children']:
        if child['name'] == next_hop:
            current_path.append(next_hop)
            return parser_navigate(child, path, current_path)
    raise NavigationException(
        'Current parser has no child element with name: %s  (path: %s)' % (
            next_hop, ' '.join(current_path)))


def _try_add_parser_attribute(data, parser, attribname):
    attribval = getattr(parser, attribname, None)
    if attribval is None:
        return
    if not isinstance(attribval, str):
        return
    if len(attribval) > 0:
        data[attribname] = attribval


def _format_usage_without_prefix(parser):
    """
    Use private argparse APIs to get the usage string without
    the 'usage: ' prefix.
    """
    fmt = parser._get_formatter()
    fmt.add_usage(parser.usage, parser._actions,
                  parser._mutually_exclusive_groups, prefix='')
    return fmt.format_help().strip()


def parse_parser(parser, data=None, **kwargs):
    if data is None:
        data = {
            'name': '',
            'usage': parser.format_usage().strip(),
            'bare_usage': _format_usage_without_prefix(parser),
            'prog': parser.prog,
        }
    _try_add_parser_attribute(data, parser, 'description')
    _try_add_parser_attribute(data, parser, 'epilog')
    for action in parser._get_positional_actions():
        if not isinstance(action, _SubParsersAction):
            continue
        helps = {}
        for item in action._choices_actions:
            helps[item.dest] = item.help

        # commands which share an existing parser are an alias,
        # don't duplicate docs
        subsection_alias = {}
        subsection_alias_names = set()
        for name, subaction in action._name_parser_map.items():
            if subaction not in subsection_alias:
                subsection_alias[subaction] = []
            else:
                subsection_alias[subaction].append(name)
                subsection_alias_names.add(name)

        for name, subaction in action._name_parser_map.items():
            if name in subsection_alias_names:
                continue
            subalias = subsection_alias[subaction]
            subaction.prog = '%s %s' % (parser.prog, name)
            subdata = {
                'name': name if not subalias else '%s (%s)' % (name, ', '.join(subalias)),
                'help': helps.get(name, ''),
                'usage': subaction.format_usage().strip(),
                'bare_usage': _format_usage_without_prefix(subaction),
            }
            parse_parser(subaction, subdata, **kwargs)
            data.setdefault('children', []).append(subdata)

    show_defaults = True
    if 'skip_default_values' in kwargs and kwargs['skip_default_values'] is True:
        show_defaults = False
    show_defaults_const = show_defaults
    if 'skip_default_const_values' in kwargs and kwargs['skip_default_const_values'] is True:
        show_defaults_const = False

    # argparse stores the different groups as a list in parser._action_groups
    # the first element of the list holds the positional arguments, the
    # second the option arguments not in groups, and subsequent elements
    # argument groups with positional and optional parameters
    action_groups = []
    for action_group in parser._action_groups:
        options_list = []
        for action in action_group._group_actions:
            if isinstance(action, _HelpAction):
                continue

            # Quote default values for string/None types
            default = action.default
            if action.default not in ['', None, True, False] and action.type in [None, str] and isinstance(action.default, str):
                default = '"%s"' % default

            # fill in any formatters, like %(default)s
            formatDict = dict(vars(action), prog=data.get('prog', ''), default=default)
            formatDict['default'] = default
            helpStr = action.help or ''  # Ensure we don't print None
            try:
                helpStr = helpStr % formatDict
            except:
                pass

            # Options have the option_strings set, positional arguments don't
            name = action.option_strings
            if name == []:
                if action.metavar is None:
                    name = [action.dest]
                else:
                    name = [action.metavar]
            # Skip lines for subcommands
            if name == ['==SUPPRESS==']:
                continue

            if isinstance(action, _StoreConstAction):
                option = {
                    'name': name,
                    'default': default if show_defaults_const else '==SUPPRESS==',
                    'help': helpStr
                }
            else:
                option = {
                    'name': name,
                    'default': default if show_defaults else '==SUPPRESS==',
                    'help': helpStr
                }
            if action.choices:
                option['choices'] = action.choices
            if "==SUPPRESS==" not in option['help']:
                options_list.append(option)

        if len(options_list) == 0:
            continue

        # Upper case "Positional Arguments" and "Optional Arguments" titles
        if action_group.title == 'optional arguments':
            action_group.title = 'Named Arguments'
        if action_group.title == 'positional arguments':
            action_group.title = 'Positional Arguments'

        group = {'title': action_group.title,
                 'description': action_group.description,
                 'options': options_list}

        action_groups.append(group)

    if len(action_groups) > 0:
        data['action_groups'] = action_groups

    return data
