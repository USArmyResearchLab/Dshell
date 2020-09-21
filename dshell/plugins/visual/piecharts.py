"""
Plugin that generates HTML+JavaScript pie charts for flow information
"""

import dshell.core
from dshell.output.output import Output

import operator
from collections import defaultdict

class VisualizationOutput(Output):
    """
    Special output class intended to only be used for this specific plugin.
    """

    _DEFAULT_FORMAT='{"value":%(data)s, "datatype":"%(datatype)s", "label":"%(label)s"},'

    _HTML_HEADER = """
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Dshell - Pie Chart Output</title>
    <script type="text/javascript" src="d3.js"></script>
    <style>
        .legend {
            font-size: 12px;
        }
        rect {
            stroke-width: 2;
        }
        .tooltip {
            background: #ffffff;
            box-shadow: 0 0 5px #999999;
            color: #333333;
            display: none;
            font-size: 12px;
            padding: 10px;
            position: absolute;
            text-align: center;
            width: 200px;
            z-index: 10;
            left: 130px;
            top: 95px;
        }
    </style>
</head>

<body>
<center>
<div id="content" width="90%">

<table border="0">
<tr>
    <td>
    <h1> Source Countries </h1>
    <div id="source_country"></div>
    </td>
    <td>
    <h1> Destination Countries </h1>
    <div id="dest_country"></div>
    </td>
</tr><tr>
    <td>
    <h1> Source ASNs </h1>
    <div id="source_asn"></div>
    </td>
    <td>
    <h1> Destination ASNs </h1>
    <div id="dest_asn"></div>
    </td>
</tr><tr>
    <td>
    <h1> Source Ports </h1>
    <div id="source_port"></div>
    </td>
    <td>
    <h1> Destination Ports </h1>
    <div id="dest_port"></div>
    </td>
</tr><tr>
    <td>
    <h1> Protocols </h1>
    <div id="protocol"></div>
    </td><td>
    </td>
</tr>
</table>

<script type="text/javascript">

var w = (window.innerWidth / 2) * 0.9,
    h = 400,
    r = Math.min(w, h) / 2.5,
    legendRectSize = 15,
    legendSpacing = 4;

var data = JSON.parse('["""

    # ignore the trailing comma by adding an empty object at the end
    _HTML_FOOTER = """{}]');

var src_country_data = [],
    dst_country_data = [],
    src_asn_data = [],
    dst_asn_data = [],
    src_ports_data = [],
    dst_ports_data = [],
    protocols_data = [];

for (var i = 0; i < data.length; i++) {
    switch (data[i]['datatype']) {
        case 'protocol':
            protocols_data.push(data[i]);
            break;
        case 'source_country':
            src_country_data.push(data[i]);
            break;
        case 'dest_country':
            dst_country_data.push(data[i]);
            break;
        case 'source_asn':
            src_asn_data.push(data[i]);
            break;
        case 'dest_asn':
            dst_asn_data.push(data[i]);
            break;
        case 'source_port':
            src_ports_data.push(data[i]);
            break;
        case 'dest_port':
            dst_ports_data.push(data[i]);
            break;
    }
}

draw_graph(src_country_data, 'source_country');
draw_graph(dst_country_data, 'dest_country');
draw_graph(src_asn_data, 'source_asn');
draw_graph(dst_asn_data, 'dest_asn');
draw_graph(src_ports_data, 'source_port');
draw_graph(dst_ports_data, 'dest_port');
draw_graph(protocols_data, 'protocol');

function draw_graph(indata, intype) {
    var color = d3.scaleOrdinal(d3.schemeCategory10);

    var tooltip = d3.select("#"+intype)
        .append('div')
        .attr('class', 'tooltip');

    tooltip.append('div')
        .attr('class', 'label');
    tooltip.append('div')
         .attr('class', 'count');
    tooltip.append('div')
        .attr('class', 'percent');

    var svg = d3.select("#"+intype)
        .append("svg:svg")
            .attr("width", w)
            .attr("height", h)
        .append("svg:g")
            .attr("transform", "translate(" + r + "," + r + ")");

    var arc = d3.arc()
        .innerRadius(0)
        .outerRadius(r);

    var pie = d3.pie()
        .value(function(d) { return d.value; })
        .sort(null);

    var path = svg.selectAll("path")
        .data(pie(indata))
        .enter()
            .append('path')
                .attr('d', arc)
                .attr('fill', function(d, i) { return color(i); });

    path.on('mouseover', function(d) {
        var total = d3.sum(indata.map(function(d) {
            return d.value;
        }));
        var percent = Math.round(1000 * d.data.value / total) / 10;
        tooltip.select('.label').html(d.data.label);
        tooltip.select('.count').html(d.data.value + ' / ' + total);
        tooltip.select('.percent').html(percent + '%');
        tooltip.style('display', 'block');
    });

    path.on('mouseout', function(d) {
        tooltip.style('display', 'none');
    });

    path.on('mousemove', function(d) {
        tooltip
            .style('top', (d3.event.pageY + 10) + 'px')
            .style('left', (d3.event.pageX + 10) + 'px');
    });

    var legend = svg.selectAll('.legend')
        .data(color.domain())
        .enter()
            .append('svg:g')
                .attr('class', 'legend')
                .attr('transform', function(d,i) {
                    var h = legendRectSize + legendSpacing;
                    var offset = h * color.domain().length / 2;
                    var horz = r + 20;
                    var vert = i * h - offset;
                    return 'translate(' + horz + ',' + vert + ')';
                });

    legend.append('rect')
        .attr('width', legendRectSize)
        .attr('height', legendRectSize)
        .style('fill', color)
        .style('stroke', color);

    legend.append('text')
        .attr('x', legendRectSize + legendSpacing)
        .attr('y', legendRectSize - legendSpacing)
        .text(function(d) {return indata[d].label; });

}

</script>
</div>
</center>
</body>
</html>

"""

    def setup(self):
        Output.setup(self)
        self.fh.write(self._HTML_HEADER)

    def close(self):
        self.fh.write(self._HTML_FOOTER)
        Output.close(self)

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name='Pie Charts',
            author='dev195',
            bpf="ip",
            description='Generates visualizations based on connections',
            longdescription="""
Generates HTML+JavaScript pie chart visualizations based on connections.

Output should be redirected to a file and placed in a directory that has the d3.js JavaScript library. Library is available for download at https://d3js.org/
""",
            output=VisualizationOutput(label=__name__),
        )

        self.top_x = 10

    def premodule(self):
        "Set each of the counter dictionaries as defaultdict(int)"
        # source
        self.s_country_count = defaultdict(int)
        self.s_asn_count = defaultdict(int)
        self.s_port_count = defaultdict(int)
        self.s_ip_count = defaultdict(int)
        # dest
        self.d_country_count = defaultdict(int)
        self.d_asn_count = defaultdict(int)
        self.d_port_count = defaultdict(int)
        self.d_ip_count = defaultdict(int)
        # protocol
        self.proto = defaultdict(int)


    def postmodule(self):
        "Write the top X results for each type of data we're counting"
        t = self.top_x + 1
        for i in sorted(self.proto.items(), reverse=True, key=operator.itemgetter(1))[:t]:
            if i[0]:
                self.write(int(i[1]), datatype="protocol", label=i[0])
        for i in sorted(self.s_country_count.items(), reverse=True, key=operator.itemgetter(1))[:t]:
            if i[0] and i[0] != '--':
                self.write(int(i[1]), datatype="source_country", label=i[0])
        for i in sorted(self.d_country_count.items(), reverse=True, key=operator.itemgetter(1))[:t]:
            if i[0] and i[0] != '--':
                self.write(int(i[1]), datatype="dest_country", label=i[0])
        for i in sorted(self.s_asn_count.items(), reverse=True, key=operator.itemgetter(1))[:t]:
            if i[0] and i[0] != '--':
                self.write(int(i[1]), datatype="source_asn", label=i[0])
        for i in sorted(self.d_asn_count.items(), reverse=True, key=operator.itemgetter(1))[:t]:
            if i[0] and i[0] != '--':
                self.write(int(i[1]), datatype="dest_asn", label=i[0])
        for i in sorted(self.s_port_count.items(), reverse=True, key=operator.itemgetter(1))[:t]:
            if i[0]:
                self.write(int(i[1]), datatype="source_port", label=i[0])
        for i in sorted(self.d_port_count.items(), reverse=True, key=operator.itemgetter(1))[:t]:
            if i[0]:
                self.write(int(i[1]), datatype="dest_port", label=i[0])

    def connection_handler(self, conn):
        "For each conn, increment the counts for the relevant dictionary keys"
        self.proto[conn.protocol] += 1
        self.s_country_count[conn.sipcc] += 1
        self.s_asn_count[conn.sipasn] += 1
        self.s_port_count[conn.sport] += 1
        self.s_ip_count[conn.sip] += 1
        self.d_country_count[conn.dipcc] += 1
        self.d_asn_count[conn.dipasn] += 1
        self.d_port_count[conn.dport] += 1
        self.d_ip_count[conn.dip] += 1
        return conn

