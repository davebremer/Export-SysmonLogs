#https://stackoverflow.com/questions/31183106/can-powershell-generate-a-plain-excel-file-with-multiple-sheets
#https://stackoverflow.com/users/4568320/avshalom
#.EXAMPLE Merge-CSVFiles -CSVPath C:\CsvFolder -XLOutput C:\ExcelFile.xlsx
Function Merge-CSVFiles {
    Param(
    $CSVPath = "C:\CSV", ## Source CSV Folder
    $XLOutput="c:\temp.xlsx" ## Output file name
    )

    $csvFiles = Get-ChildItem ("$CSVPath\*") -Include *.csv
    $Excel = New-Object -ComObject excel.application 
    $Excel.visible = $false
    $Excel.sheetsInNewWorkbook = $csvFiles.Count
    $workbooks = $excel.Workbooks.Add()
    $CSVSheet = 1

    Foreach ($CSV in $Csvfiles) {
        $worksheets = $workbooks.worksheets
        $CSVFullPath = $CSV.FullName
        $SheetName = ($CSV.name -split "\.")[0]
        $worksheet = $worksheets.Item($CSVSheet)
        $worksheet.Name = $SheetName
        $TxtConnector = ("TEXT;" + $CSVFullPath)
        $CellRef = $worksheet.Range("A1")
        $Connector = $worksheet.QueryTables.add($TxtConnector,$CellRef)
        $worksheet.QueryTables.item($Connector.name).TextFileCommaDelimiter = $True
        $worksheet.QueryTables.item($Connector.name).TextFileParseType  = 1
        $worksheet.QueryTables.item($Connector.name).Refresh()
        $worksheet.QueryTables.item($Connector.name).delete()
        $worksheet.UsedRange.EntireColumn.AutoFit()
        $CSVSheet++

    }

    $workbooks.SaveAs($XLOutput,51)
    $workbooks.Saved = $true
    $workbooks.Close()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbooks) | Out-Null
    $excel.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

}