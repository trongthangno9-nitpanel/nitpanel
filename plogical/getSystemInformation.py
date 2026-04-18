import platform
import os
import datetime
import math
import argparse

class SystemInformation:
    now = datetime.datetime.now()
    olsReport = ""

    @staticmethod
    def cpuLoad():
        return os.getloadavg()

    @staticmethod
    def getOSName():

        OSName = platform.platform()
        data =  OSName.split("-")

        checker = 0
        finalOSName = ""

        for items in data:

            if checker == 1:
                finalOSName = items
                break

            if items == "with":
                checker = 1

        return finalOSName

    @staticmethod
    def getCurrentSystemTime():
        return SystemInformation.now.strftime("%I:%M")

    @staticmethod
    def currentWeekDay():
        return SystemInformation.now.strftime("%a")

    @staticmethod
    def currentMonth():
        return SystemInformation.now.strftime("%B")

    @staticmethod
    def currentYear():
        return SystemInformation.now.strftime("%Y")

    @staticmethod
    def currentDay():
        return SystemInformation.now.strftime("%d")

    @staticmethod
    def getAllInfo():
        OSName = SystemInformation.getOSName()
        loadAverage = SystemInformation.cpuLoad()
        currentTime = SystemInformation.getCurrentSystemTime()
        weekDayNameInString = SystemInformation.currentWeekDay()
        currentMonthName = SystemInformation.currentMonth()
        currentDayInDecimal = SystemInformation.currentDay()
        currentYear = SystemInformation.currentYear()
        loadAverage = list(loadAverage)
        one = loadAverage[0]
        two = loadAverage[1]
        three = loadAverage[2]

        data = {"weekDayNameInString": weekDayNameInString, "currentMonthName": currentMonthName,
         "currentDayInDecimal": currentDayInDecimal, "currentYear": currentYear, "OSName": OSName,
         "loadAVG": loadAverage, "currentTime": currentTime, "one":one,"two":two,"three":three}

        return data


    @staticmethod
    def getSystemInformation():
        try:
            import psutil
            
            # Get usage percentages
            ram_percent = int(math.floor(psutil.virtual_memory()[2]))
            cpu_percent = int(math.floor(psutil.cpu_percent()))
            disk_percent = int(math.floor(psutil.disk_usage('/')[3]))
            
            # Get total system information
            cpu_cores = psutil.cpu_count()
            ram_total_mb = int(psutil.virtual_memory().total / (1024 * 1024))
            disk_total_gb = int(psutil.disk_usage('/').total / (1024 * 1024 * 1024))
            disk_free_gb = int(psutil.disk_usage('/').free / (1024 * 1024 * 1024))
            
            # Get uptime
            uptime_seconds = int(psutil.boot_time())
            current_time = int(datetime.datetime.now().timestamp())
            uptime_diff = current_time - uptime_seconds
            
            days = uptime_diff // 86400
            hours = (uptime_diff % 86400) // 3600
            minutes = (uptime_diff % 3600) // 60
            
            if days > 0:
                uptime_str = f"{days}D, {hours}H, {minutes}M"
            else:
                uptime_str = f"{hours}H, {minutes}M"
            
            SystemInfo = {
                'ramUsage': ram_percent, 
                'cpuUsage': cpu_percent, 
                'diskUsage': disk_percent,
                'cpuCores': cpu_cores,
                'ramTotalMB': ram_total_mb,
                'diskTotalGB': disk_total_gb,
                'diskFreeGB': disk_free_gb,
                'uptime': uptime_str
            }
            return SystemInfo
        except:
            SystemInfo = {'ramUsage': 0,
                          'cpuUsage': 0,
                          'diskUsage': 0,
                          'cpuCores': 0,
                          'ramTotalMB': 0,
                          'diskTotalGB': 0,
                          'diskFreeGB': 0,
                          'uptime': 'N/A'}
            return SystemInfo

    @staticmethod
    def cpuRamDisk():
        try:
            import psutil
            SystemInfo = {'ramUsage': int(math.floor(psutil.virtual_memory()[2])),
                          'cpuUsage': int(math.floor(psutil.cpu_percent())),
                          'diskUsage': int(math.floor(psutil.disk_usage('/')[3]))}
        except:
            SystemInfo = {'ramUsage': 0,
                          'cpuUsage': 0,
                          'diskUsage': 0}

        return SystemInfo

    @staticmethod
    def GetRemainingDiskUsageInMBs():
        import psutil

        total_disk = psutil.disk_usage('/').total / (1024 * 1024)  # Total disk space in MB
        used_disk = psutil.disk_usage('/').used / (1024 * 1024)  # Used disk space in MB
        free_disk = psutil.disk_usage('/').free / (1024 * 1024)  # Free disk space in MB
        percent_used = psutil.disk_usage('/').percent  # Percentage of disk used

        return used_disk, free_disk, percent_used

    @staticmethod
    def populateOLSReport():
        SystemInformation.olsReport = open("/tmp/lshttpd/.rtreport", "r").readlines()



def main():

    parser = argparse.ArgumentParser(description='NitPanel Installer')
    parser.add_argument('function', help='Specific a function to call!')

    args = parser.parse_args()

    if args.function == "populateOLSReport":
        SystemInformation.populateOLSReport()


if __name__ == "__main__":
    main()