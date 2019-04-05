import sys; # args
import os; # files
from fuzzywuzzy import fuzz;
from fuzzywuzzy import process;


class Storage:
    def __init__(self):
        self.file_trusted = "trusted.csv";
        self.file_untrusted = "untrusted.csv";

    def _add(self, file, url):
        with open(file, "a+") as f:
            f.write(url+'\n');

    def _get(self, file) -> list:
        file_contents = "";
        with open(file, "r+") as f:
            file_contents = f.read().splitlines();
        return file_contents;

    def get_trusted(self) -> list:
        return self._get(self.file_trusted);

    def add_trusted(self, url) -> object:
        self._add(self.file_trusted, url);
        return self;

    def get_untrusted(self) -> list:
        return self._get(self.file_untrusted);

    def add_untrusted(self, url) -> object:
        self._add(self.file_untrusted, url);
        return self;


class Compare:
    @staticmethod
    def fuzzy(url, array, size) -> list:
        fuzzy_result = process.extract(url, array, Compare.processor_std, fuzz.ratio, size);
        fuzzy_matches_count = len(fuzzy_result);
        fuzzy_matches_total = 0;
        fuzzy_matches_confidence = 0.0;
        for match in range(0, fuzzy_matches_count):
            fuzzy_matches_total += fuzzy_result[match][1];
        fuzzy_matches_confidence = (fuzzy_matches_total / (fuzzy_matches_count * 100)) * 100;
        return [fuzzy_matches_confidence, fuzzy_matches_count, fuzzy_result[0]];

    @staticmethod
    def processor_std(a) -> str:
        return a;

    @staticmethod
    def processor_sql(a) -> str:
        # tbd.
        return a;

    @staticmethod
    def sql_coverage(a) -> float:
        sql_keywords = ["select", "select", "avg", "union", "from", "char", "version", "'", "\"", "`", "*"];
        sql_keyword_coverage = 0;
        for word in sql_keywords:
            if word.lower() in a:
                sql_keyword_coverage += 1;
        return (sql_keyword_coverage/len(sql_keywords)) * 100;


def main(args):
    if len(args) < 2:
        print("Specify a partial URL");
        exit(0);
    else:
        input_url = args[1];

        bias_untrusted = 0;
        bias_trusted = 0;

        storage = Storage();
        storage_untrusted = storage.get_untrusted();
        storage_trusted = storage.get_trusted();
        dataset_size = len(storage_untrusted) if len(storage_untrusted) < len(storage_trusted) else len(storage_trusted);
        res_sql_coverage = Compare.sql_coverage(input_url);
        res_untrusted = Compare.fuzzy(input_url, storage_untrusted, dataset_size);
        res_trusted = Compare.fuzzy(input_url, storage_trusted, dataset_size);
        res_trusted_percent = res_trusted[0];
        res_untrusted_percent = res_untrusted[0];
        res_trusted_percent_topmatch = res_trusted[2][1];
        res_untrusted_percent_topmatch = res_untrusted[2][1];
        res_trusted_untrusted_top_ratio = fuzz.ratio(res_trusted[2][0], res_untrusted[2][0]);

        print("query: " + input_url);
        print("sql cov: " + str(res_sql_coverage));
        print("dsize: " + str(dataset_size));
        print("threat: " + str(res_untrusted_percent));
        print("trust: " + str(res_trusted_percent));
        #print("similar: " + str(res_trusted_untrusted_top_ratio));

        print("top threat: " + str(res_untrusted[2]));
        print("top trust: " + str(res_trusted[2]));

        if res_sql_coverage > 7:
            bias_untrusted += 1;

        if res_sql_coverage > 20:
            bias_untrusted += 1;

        if res_trusted_percent_topmatch > 99:
            bias_trusted += 2;

        elif res_untrusted_percent > 50:
            bias_untrusted += 1;

        # Compare the top trusted and untrusted match results percentages
        if res_trusted_percent_topmatch > res_untrusted_percent_topmatch:
            bias_trusted += 1;
        elif res_trusted_percent_topmatch < res_untrusted_percent_topmatch:
            bias_untrusted += 1;

        # the 'certified trusted' threshold is 80%
        if res_trusted_percent > 79:
            bias_trusted += 1;
        elif res_trusted_percent < 80:
            # if trusted percent is below 80, and untrusted is higher than that
            if res_untrusted_percent > res_trusted_percent:
                bias_untrusted +=1;
            # untrusted urls can have some small things added to them
            if abs(res_untrusted_percent - res_trusted_percent) < 10:
                bias_untrusted += 1;

        print("\n");

        # Save the results to the storage
        if bias_trusted == bias_untrusted:
            print("decision inconclusive, human oversight necessary");
        elif bias_trusted > bias_untrusted:
            if res_untrusted_percent < 30:
                print("trusted (saving to memory)");
                storage.add_trusted(input_url);
            else:
                print("trusted (not saving)");
        else:
            print("untrusted (saving to memory)");
            storage.add_untrusted(input_url);

        print("trust: " + str(bias_trusted) + "\nthreat: " + str(bias_untrusted));

main(sys.argv);
