var stringToColor = function(str) {
    var hash = 0;
    for(var i=0; i < str.length; i++) {
        hash = str.charCodeAt(i) + ((hash << 3) - hash);
    }
    var color = Math.abs(hash).toString(16).substring(0, 6);
    return "#" + '000000'.substring(0, 6 - color.length) + color;
}