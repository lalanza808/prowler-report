from jinja2 import Template
from os import path
from csv import reader


def run():
    csv_data = {}
    totals = {
        'accounts': [],
        'regions': [],
        'scan_results': [],
        'passes': [],
        'fails': [],
        'infos': [],
        'all_by_sev': {},
        'passes_by_sev': {},
        'fails_by_sev': {},
        'infos_by_sev': {},
        'results_by_check_id': {}
    }

    with open('template.html') as f:
        tpl = f.read()

    with open('prowler-test.csv') as csv_file:
        csv_reader = reader(csv_file, delimiter=',')
        next(csv_reader, None)
        for idx, row in enumerate(csv_reader):
            csv_data[idx] = {
                'profile': row[0],
                'account_id': row[1],
                'region':  row[2],
                'title_id':  row[3],
                'result': row[4],
                'scored': row[5],
                'level':  row[6],
                'title_text':  row[7],
                'notes': row[8],
                'compliance': row[9],
                'severity': row[10],
                'service_name': row[11],
            }

            d = csv_data[idx]
            t = totals

            # Capture results summary
            rs = 'results_summary'
            rl = d['result'].lower()
            if rs not in totals:
                t[rs] = dict()
            if rl not in t[rs]:
                t[rs][rl] = list()
            t[rs][rl].append(d)

            if d['title_id'] not in t['results_by_check_id']:
                t['results_by_check_id'][d['title_id']] = csv_data[idx]

            if d['account_id'] not in t['accounts']:
                t['accounts'].append(d['account_id'])

            if d['region'] not in t['regions']:
                t['regions'].append(d['region'])

            t['scan_results'].append(idx)

            l = d['severity'].lower()
            if l not in t['all_by_sev']:
                t['all_by_sev'][l] = list()
            if idx not in t['all_by_sev'][l]:
                t['all_by_sev'][l].append(idx)

    # list(OrderedDict.fromkeys([x['severity'].lower() for x in data.values() if x['severity'].lower()]))

    # print(totals['results_summary'])

    tpl = Template(tpl)
    rendered = tpl.render(data=csv_data, totals=totals)

    with open('report.html', 'w') as f:
        f.write(rendered)
        print('Generated report as "report.html"')


if __name__ == '__main__':
    run()
